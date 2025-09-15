# app.py
import os
import asyncio
import time
import base64
import json
from typing import Tuple, Optional
from functools import wraps

import httpx
import aioredis
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, constr
from cachetools import TTLCache
from Crypto.Cipher import AES
from google.protobuf import json_format, message
from google.protobuf.message import Message
import logging

# -----------------------
# Logging
# -----------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ff_service")

# -----------------------
# ENV VARS (set securely)
# -----------------------
MAIN_KEY = base64.b64decode(os.getenv("MAIN_KEY_BASE64", ""))
MAIN_IV = base64.b64decode(os.getenv("MAIN_IV_BASE64", ""))
RELEASEVERSION = os.getenv("RELEASE_VERSION", "OB50")
USERAGENT = os.getenv("USER_AGENT", "Dalvik/2.1.0 (Linux; U; Android 13)")
REDIS_URL = os.getenv("REDIS_URL", None)
ACCOUNT_CREDENTIALS = json.loads(os.getenv("ACCOUNT_CREDENTIALS_JSON", "{}"))
SUPPORTED_REGIONS = set(os.getenv("SUPPORTED_REGIONS",
                                 "IND,BR,US,SAC,NA,SG,RU,ID,TW,VN,TH,ME,PK,CIS,BD,EUROPE").split(","))

# -----------------------
# Proto imports (ensure proto package is on PYTHONPATH)
# -----------------------
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2  # noqa: E402

# -----------------------
# Globals / Pools
# -----------------------
app = FastAPI(title="FF Account Info Service")
local_cache = TTLCache(maxsize=200, ttl=300)
redis: Optional[aioredis.Redis] = None
http_client: Optional[httpx.AsyncClient] = None
region_locks = {}
SEMAPHORE = asyncio.Semaphore(int(os.getenv("INSTANCE_CONCURRENCY", "200")))
TOKEN_TTL = int(os.getenv("TOKEN_TTL", "25200"))  # seconds

# -----------------------
# Utils: AES CBC PKCS7 padding
# -----------------------
def pad(data: bytes) -> bytes:
    pad_len = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([pad_len]) * pad_len

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext))

# -----------------------
# Protobuf helpers
# -----------------------
def decode_protobuf(encoded: bytes, message_type: message.Message) -> message.Message:
    inst = message_type()
    try:
        inst.ParseFromString(encoded)
    except Exception as e:
        raise ValueError(f"Protobuf parse error: {e}")
    return inst

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    inst = proto_message
    try:
        json_format.ParseDict(json.loads(json_data), inst)
        return inst.SerializeToString()
    except Exception as e:
        raise ValueError(f"JSON->Proto serialization error: {e}")

# -----------------------
# Redis helpers
# -----------------------
async def redis_connect():
    global redis
    if not REDIS_URL:
        logger.warning("REDIS_URL not configured, using local in-memory cache only")
        return None
    redis = await aioredis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
    logger.info("Connected to Redis")
    return redis

async def cache_get(key: str):
    if redis:
        return await redis.get(key)
    return local_cache.get(key)

async def cache_set(key: str, value: str, ttl: int):
    if redis:
        await redis.set(key, value, ex=ttl)
    else:
        local_cache[key] = value

# -----------------------
# HTTP helpers: retry/backoff
# -----------------------
async def post_with_retries(url: str, data: bytes, headers: dict, retries=3, backoff=0.5, timeout=15.0):
    last_exc = None
    for i in range(retries):
        try:
            resp = await http_client.post(url, data=data, headers=headers, timeout=timeout)
            resp.raise_for_status()
            return resp
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            last_exc = e
            wait = backoff * (2 ** i)
            logger.warning("Request error to %s: %s. Retrying in %.2fs (attempt %d/%d)", url, e, wait, i+1, retries)
            await asyncio.sleep(wait)
    logger.error("All retries failed for %s", url)
    raise last_exc

# -----------------------
# Account credentials
# -----------------------
async def get_account_credentials(region: str) -> str:
    r = region.upper()
    val = ACCOUNT_CREDENTIALS.get(r)
    if val:
        return val
    return ACCOUNT_CREDENTIALS.get("DEFAULT", "")

# -----------------------
# Obtain access token from Garena endpoint
# -----------------------
async def obtain_access_token_for_account(account_payload: str) -> Tuple[str, str]:
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "User-Agent": USERAGENT,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    resp = await post_with_retries(url, data=account_payload.encode(), headers=headers, retries=3)
    data = resp.json()
    return data.get("access_token", ""), data.get("open_id", "")

# -----------------------
# Create JWT/Login and cache
# -----------------------
async def create_jwt_and_cache(region: str):
    lock = region_locks.setdefault(region, asyncio.Lock())
    async with lock:
        cached = await cache_get(f"token:{region}")
        if cached:
            info = json.loads(cached)
            if time.time() < info.get("expires_at", 0):
                return info

        account = await get_account_credentials(region)
        if not account:
            raise ValueError("No credentials configured for region")

        token_val, open_id = await obtain_access_token_for_account(account)
        body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
        proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
        payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
        url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
            'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream", 'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1", 'ReleaseVersion': RELEASEVERSION
        }
        resp = await post_with_retries(url, data=payload, headers=headers, retries=3)
        try:
            msg_json = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
        except Exception as e:
            raise ValueError("Failed to parse login response") from e

        stored = {
            'token': f"Bearer {msg_json.get('token','0')}",
            'region': msg_json.get('lockRegion','0'),
            'server_url': msg_json.get('serverUrl','0'),
            'expires_at': time.time() + TOKEN_TTL - 30
        }
        await cache_set(f"token:{region}", json.dumps(stored), TOKEN_TTL)
        logger.info("Cached token for region %s", region)
        return stored

async def get_token_info(region: str):
    raw = await cache_get(f"token:{region}")
    if raw:
        info = json.loads(raw)
        if time.time() < info.get("expires_at", 0):
            return info['token'], info['region'], info['server_url']
    info = await create_jwt_and_cache(region)
    return info['token'], info['region'], info['server_url']

# -----------------------
# Main: GetAccountInformation
# -----------------------
async def GetAccountInformation(uid: str, unk: str, region: str, endpoint: str):
    region = region.upper()
    if region not in SUPPORTED_REGIONS:
        raise HTTPException(status_code=400, detail="Unsupported region")

    if not uid.isdigit() or len(uid) < 5 or len(uid) > 20:
        raise HTTPException(status_code=400, detail="Invalid UID format")

    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

    token, lock, server = await get_token_info(region)
    if not server:
        raise HTTPException(status_code=502, detail="No server URL returned from login")

    headers = {
        'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream", 'Expect': "100-continue",
        'Authorization': token, 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }

    async with SEMAPHORE:
        resp = await post_with_retries(server + endpoint, data=data_enc, headers=headers, retries=3)

    try:
        parsed = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))
    except Exception as e:
        logger.exception("Failed to decode account info")
        raise HTTPException(status_code=502, detail=f"Failed to decode server response: {e}")

    return parsed

# -----------------------
# Response formatting
# -----------------------
def format_response(data: dict):
    b = data.get("basicInfo", {})
    profile = data.get("profileInfo", {})
    clan = data.get("clanBasicInfo", {})
    return {
        "AccountInfo": {
            "AccountAvatarId": b.get("headPic"),
            "AccountBPBadges": b.get("badgeCnt"),
            "AccountBPID": b.get("badgeId"),
            "AccountBannerId": b.get("bannerId"),
            "AccountCreateTime": b.get("createAt"),
            "AccountEXP": b.get("exp"),
            "AccountLastLogin": b.get("lastLoginAt"),
            "AccountLevel": b.get("level"),
            "AccountLikes": b.get("liked"),
            "AccountName": b.get("nickname"),
            "AccountRegion": b.get("region"),
            "AccountSeasonId": b.get("seasonId"),
            "AccountType": b.get("accountType"),
            "BrMaxRank": b.get("maxRank"),
            "BrRankPoint": b.get("rankingPoints"),
            "CsMaxRank": b.get("csMaxRank"),
            "CsRankPoint": b.get("csRankingPoints"),
            "EquippedWeapon": b.get("weaponSkinShows", []),
            "ReleaseVersion": b.get("releaseVersion"),
            "ShowBrRank": b.get("showBrRank"),
            "ShowCsRank": b.get("showCsRank"),
            "Title": b.get("title")
        },
        "AccountProfileInfo": {
            "EquippedOutfit": profile.get("clothes", []),
            "EquippedSkills": profile.get("equipedSkills", [])
        },
        "GuildInfo": {
            "GuildCapacity": clan.get("capacity"),
            "GuildID": str(clan.get("clanId")) if clan.get("clanId") else None,
            "GuildLevel": clan.get("clanLevel"),
            "GuildMember": clan.get("memberNum"),
            "GuildName": clan.get("clanName"),
            "GuildOwner": str(clan.get("captainId")) if clan.get("captainId") else None
        },
        "captainBasicInfo": data.get("captainBasicInfo", {}),
        "creditScoreInfo": data.get("creditScoreInfo", {}),
        "petInfo": data.get("petInfo", {}),
        "socialinfo": data.get("socialInfo", {})
    }

# -----------------------
# API Models & Routes
# -----------------------
class PlayerQuery(BaseModel):
    uid: constr(min_length=5, max_length=20, regex=r'^\d+$')
    region: constr(min_length=2, max_length=10)

@app.on_event("startup")
async def startup_event():
    global http_client
    http_client = httpx.AsyncClient(timeout=30.0, limits=httpx.Limits(max_keepalive_connections=100, max_connections=300))
    await redis_connect()
    logger.info("Service startup complete")

@app.on_event("shutdown")
async def shutdown_event():
    global http_client, redis
    if http_client:
        await http_client.aclose()
    if redis:
        await redis.close()
    logger.info("Service shutdown complete")

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    # simple IP rate-limiter hook can be added here if desired
    start = time.time()
    response = await call_next(request)
    process_time = time.time() - start
    response.headers["X-Process-Time"] = str(process_time)
    return response

@app.get("/player-info")
async def get_account_info(uid: str = Query(...), region: str = Query(...)):
    try:
        data = await GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow")
        return JSONResponse(content=format_response(data), status_code=200)
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.exception("Unhandled error in /player-info")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/refresh")
async def refresh_tokens():
    for r in SUPPORTED_REGIONS:
        try:
            await create_jwt_and_cache(r)
        except Exception as e:
            logger.warning("Failed to refresh region %s: %s", r, e)
    return {"message": "Tokens refreshed (attempted all regions)"}
