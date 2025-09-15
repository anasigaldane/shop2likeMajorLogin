# =================== IMPORTS ===================
import asyncio
import time
import httpx
import json
import logging
import base64
from collections import defaultdict
from typing import Tuple
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format
from google.protobuf.message import Message
from Crypto.Cipher import AES

# =================== CONFIG ===================
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB50"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}
TOKEN_TTL = 25200  # 7 hours
REQUEST_TIMEOUT = 10

# =================== LOGGING ===================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

# =================== GLOBALS ===================
cached_tokens = defaultdict(dict)

# =================== CRYPTO HELPERS ===================
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

# =================== PROTO HELPERS ===================
def decode_protobuf(encoded_data: bytes, proto_type: Message) -> Message:
    instance = proto_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

# =================== UTILS ===================
def safe_get(d: dict, keys: list, default=None):
    for key in keys:
        if isinstance(d, dict):
            d = d.get(key, default)
        else:
            return default
    return d

# =================== ACCOUNT HELPERS ===================
def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "IND":
        return "uid=3947622285&password=92AAF030CF53C1DD509C3C6070BC79004C64A819F34AB8E07BD0ABCDC424D511"
    elif r == "BD":
        return "uid=3957595605&password=7203510AB3D87E06CE54FC93ABE40D48AA6AEA55E2DEA2D2AA3487CBB20650D7"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=3788023112&password=5356B7495AC2AD04C0A483CF234D6E56FB29080AC2461DD51E0544F8D455CC24"
    else:
        return "uid=4167202140&password=7F6CDF48F387A1D78010CB3359A3660BCFC5AA0040A0118D0287122973DD1FE3"

# =================== TOKEN MANAGEMENT ===================
async def get_access_token(account: str) -> Tuple[str, str]:
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
    return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt(region: str):
    account = get_account_credentials(region)
    token_val, open_id = await get_access_token(account)
    body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        resp = await client.post(url, data=payload, headers=headers)
    msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
    cached_tokens[region] = {
        'token': f"Bearer {msg.get('token','0')}",
        'region': msg.get('lockRegion','0'),
        'server_url': msg.get('serverUrl','0'),
        'expires_at': time.time() + TOKEN_TTL
    }
    logging.info(f"JWT created for region {region}")

async def get_token_info(region: str) -> Tuple[str, str, str]:
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    await create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

# =================== API INTERACTIONS ===================
async def GetAccountInformation(uid, unk, region, endpoint):
    region = region.upper()
    if region not in SUPPORTED_REGIONS:
        raise ValueError(f"Unsupported region: {region}")
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token_info(region)
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': token,
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        resp = await client.post(server + endpoint, data=data_enc, headers=headers)
    return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))

# =================== RESPONSE FORMATTING ===================
def format_response(data):
    return {
        "AccountInfo": {
            "AccountAvatarId": safe_get(data, ["basicInfo","headPic"]),
            "AccountBPBadges": safe_get(data, ["basicInfo","badgeCnt"]),
            "AccountBPID": safe_get(data, ["basicInfo","badgeId"]),
            "AccountBannerId": safe_get(data, ["basicInfo","bannerId"]),
            "AccountCreateTime": safe_get(data, ["basicInfo","createAt"]),
            "AccountEXP": safe_get(data, ["basicInfo","exp"]),
            "AccountLastLogin": safe_get(data, ["basicInfo","lastLoginAt"]),
            "AccountLevel": safe_get(data, ["basicInfo","level"]),
            "AccountLikes": safe_get(data, ["basicInfo","liked"]),
            "AccountName": safe_get(data, ["basicInfo","nickname"]),
            "AccountRegion": safe_get(data, ["basicInfo","region"]),
            "AccountSeasonId": safe_get(data, ["basicInfo","seasonId"]),
            "AccountType": safe_get(data, ["basicInfo","accountType"]),
            "BrMaxRank": safe_get(data, ["basicInfo","maxRank"]),
            "BrRankPoint": safe_get(data, ["basicInfo","rankingPoints"]),
            "CsMaxRank": safe_get(data, ["basicInfo","csMaxRank"]),
            "CsRankPoint": safe_get(data, ["basicInfo","csRankingPoints"]),
            "EquippedWeapon": safe_get(data, ["basicInfo","weaponSkinShows"], []),
            "ReleaseVersion": safe_get(data, ["basicInfo","releaseVersion"]),
            "ShowBrRank": safe_get(data, ["basicInfo","showBrRank"]),
            "ShowCsRank": safe_get(data, ["basicInfo","showCsRank"]),
            "Title": safe_get(data, ["basicInfo","title"])
        },
        "AccountProfileInfo": {
            "EquippedOutfit": safe_get(data, ["profileInfo","clothes"], []),
            "EquippedSkills": safe_get(data, ["profileInfo","equipedSkills"], [])
        },
        "GuildInfo": {
            "GuildCapacity": safe_get(data, ["clanBasicInfo","capacity"]),
            "GuildID": str(safe_get(data, ["clanBasicInfo","clanId"])),
            "GuildLevel": safe_get(data, ["clanBasicInfo","clanLevel"]),
            "GuildMember": safe_get(data, ["clanBasicInfo","memberNum"]),
            "GuildName": safe_get(data, ["clanBasicInfo","clanName"]),
            "GuildOwner": str(safe_get(data, ["clanBasicInfo","captainId"]))
        },
        "captainBasicInfo": safe_get(data, ["captainBasicInfo"], {}),
        "creditScoreInfo": safe_get(data, ["creditScoreInfo"], {}),
        "petInfo": safe_get(data, ["petInfo"], {}),
        "socialinfo": safe_get(data, ["socialInfo"], {})
    }

# =================== FASTAPI APP ===================
app = FastAPI()

@app.get("/player-info")
async def get_player_info(uid: str = Query(...), region: str = Query(...)):
    try:
        data = await GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow")
        formatted = format_response(data)
        return JSONResponse(formatted)
    except Exception as e:
        logging.error(f"Failed to fetch account info: {e}")
        raise HTTPException(status_code=500, detail="Invalid UID or Region. Please check and try again.")

@app.get("/refresh")
async def refresh_tokens():
    try:
        tasks = [create_jwt(r) for r in SUPPORTED_REGIONS]
        await asyncio.gather(*tasks)
        return {"message": "Tokens refreshed for all regions."}
    except Exception as e:
        logging.error(f"Failed to refresh tokens: {e}")
        raise HTTPException(status_code=500, detail=f"Refresh failed: {e}")
