# app.py (محسّن)
import os
import time
import base64
import json
import logging
import threading
import socket
from typing import Tuple, Optional
from collections import defaultdict
from functools import wraps
from datetime import timedelta

import httpx
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from cachetools import TTLCache
from Crypto.Cipher import AES
from google.protobuf import json_format, message

# ---------- Optional redis (if installed and REDIS_URL provided) ----------
try:
    import redis as redis_sync
except Exception:
    redis_sync = None

# ---------- Settings (env) ----------
MAIN_KEY_B64 = os.getenv("MAIN_KEY_BASE64", "WWcmdGMlREV1aDYlWmNeOA==")
MAIN_IV_B64 = os.getenv("MAIN_IV_BASE64", "Nm95WkRyMjJFM3ljaGpNJQ==")
RELEASEVERSION = os.getenv("RELEASE_VERSION", "OB50")
USERAGENT = os.getenv("USER_AGENT", "Dalvik/2.1.0 (Linux; U; Android 13)")
REDIS_URL = os.getenv("REDIS_URL", "").strip() or None
INSTANCE_CONCURRENCY = int(os.getenv("INSTANCE_CONCURRENCY", "200"))
TOKEN_TTL = int(os.getenv("TOKEN_TTL", "25200"))
RATE_LIMIT_RPS = int(os.getenv("RATE_LIMIT_RPS", "50"))  # per-IP default
RATE_LIMIT_BURST = int(os.getenv("RATE_LIMIT_BURST", "100"))

# region credentials (local default)
# keep these same as original get_account_credentials mapping if needed
ACCOUNT_CREDENTIALS = json.loads(os.getenv("ACCOUNT_CREDENTIALS_JSON", "{IND":"uid=3947622285&password=92AAF030CF53C1DD509C3C6070BC79004C64A819F34AB8E07BD0ABCDC424D511","BD":"uid=3957595605&password=7203510AB3D87E06CE54FC93ABE40D48AA6AEA55E2DEA2D2AA3487CBB20650D7","DEFAULT":"uid=4167202140&password=7F6CDF48F387A1D78010CB3359A3660BCFC5AA0040A0118D0287122973DD1FE3}"))
SUPPORTED_REGIONS = set(os.getenv("SUPPORTED_REGIONS",
    "IND,BR,US,SAC,NA,SG,RU,ID,TW,VN,TH,ME,PK,CIS,BD,EUROPE").split(","))

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ff_service")
# Hide debug logs in production unless env DEBUG=1
if os.getenv("DEBUG", "0") != "1":
    logger.setLevel(logging.INFO)

# ---------- Decode AES keys safely ----------
def safe_b64decode(s: str) -> bytes:
    try:
        return base64.b64decode(s)
    except Exception:
        return b""

MAIN_KEY = safe_b64decode(MAIN_KEY_B64)
MAIN_IV = safe_b64decode(MAIN_IV_B64)

if len(MAIN_KEY) not in (16, 24, 32) or len(MAIN_IV) != 16:
    logger.warning("MAIN_KEY/MAIN_IV lengths are not valid AES sizes. AES operations will fail until corrected.")

# ---------- Proto imports (ensure proto package on PYTHONPATH) ----------
# You already have these in your repo
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2  # noqa: E402

# ---------- Flask app ----------
app = Flask(__name__)
CORS(app)

# ---------- Caches and storage ----------
# in-memory TTL cache as fallback
local_cache = TTLCache(maxsize=1000, ttl=TOKEN_TTL)
# cached_tokens used as fallback when Redis not configured
cached_tokens = defaultdict(dict)  # region -> dict

# ---------- Redis client (optional) ----------
redis_client = None
if REDIS_URL and redis_sync:
    try:
        redis_client = redis_sync.from_url(REDIS_URL, decode_responses=True)
        # quick ping
        redis_client.ping()
        logger.info("Connected to Redis")
    except Exception as e:
        logger.warning("Redis connection failed; continuing with in-memory cache. Reason: %s", e)
        redis_client = None
elif REDIS_URL and not redis_sync:
    logger.warning("REDIS_URL provided but redis package not installed; install 'redis' to enable Redis support")

# ---------- HTTP client (sync) with connection pooling ----------
# we use a single httpx.Client for pooling (thread-safe)
_http_client = httpx.Client(timeout=15.0, limits=httpx.Limits(max_keepalive_connections=100, max_connections=500),
                            headers={"User-Agent": USERAGENT})

# ---------- Utility: AES CBC PKCS7 ----------
def _pad(b: bytes) -> bytes:
    pad_len = AES.block_size - (len(b) % AES.block_size)
    return b + bytes([pad_len]) * pad_len

def aes_cbc_encrypt_sync(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    if not key or not iv:
        raise ValueError("AES key/iv missing")
    if len(iv) != 16 or len(key) not in (16, 24, 32):
        raise ValueError("Invalid AES key/iv sizes")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(_pad(plaintext))

# ---------- Protobuf helpers (sync-friendly) ----------
def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    inst = message_type()
    inst.ParseFromString(encoded_data)
    return inst

def json_to_proto_sync(json_data: str, proto_message: message.Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

# ---------- Safe network helpers with retries ----------
def post_with_retries_sync(url: str, data: bytes, headers: dict, retries=3, backoff=0.5, timeout=15.0) -> httpx.Response:
    last_exc = None
    for i in range(retries):
        try:
            r = _http_client.post(url, content=data, headers=headers, timeout=timeout)
            r.raise_for_status()
            return r
        except httpx.HTTPStatusError as he:
            # 4xx/5xx responses: don't mask but retry on server errors
            last_exc = he
            status = he.response.status_code
            if 400 <= status < 500:
                # client error - don't retry
                logger.warning("Client error %d from %s: %s", status, url, he)
                raise
            logger.warning("HTTPStatusError to %s: %s (attempt %d/%d)", url, he, i+1, retries)
        except Exception as e:
            last_exc = e
            wait = backoff * (2 ** i)
            logger.warning("Request error to %s: %s - retrying in %.2fs (%d/%d)", url, e, wait, i+1, retries)
            time.sleep(wait)
    # if we exit loop without return, re-raise last
    logger.error("All retries failed for %s: %s", url, last_exc)
    raise last_exc

# ---------- Account credentials fallback (keeps original mapping) ----------
def get_account_credentials(region: str) -> str:
    r = (region or "").upper()
    if r == "IND":
        return "uid=3947622285&password=92AAF030CF53C1DD509C3C6070BC79004C64A819F34AB8E07BD0ABCDC424D511"
    elif r == "BD":
        return "uid=3957595605&password=7203510AB3D87E06CE54FC93ABE40D48AA6AEA55E2DEA2D2AA3487CBB20650D7"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=3788023112&password=5356B7495AC2AD04C0A483CF234D6E56FB29080AC2461DD51E0544F8D455CC24"
    else:
        return "uid=4167202140&password=7F6CDF48F387A1D78010CB3359A3660BCFC5AA0040A0118D0287122973DD1FE3"

# ---------- Token management (sync) ----------
region_locks = defaultdict(threading.Lock)

def cache_get(key: str) -> Optional[str]:
    if redis_client:
        try:
            return redis_client.get(key)
        except Exception as e:
            logger.warning("Redis GET failed: %s", e)
    # fallback
    return local_cache.get(key)

def cache_set(key: str, value: str, ttl: int):
    if redis_client:
        try:
            redis_client.set(key, value, ex=ttl)
            return
        except Exception as e:
            logger.warning("Redis SET failed: %s", e)
    local_cache[key] = value

def get_access_token_sync(account: str) -> Tuple[str, str]:
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
    resp = post_with_retries_sync(url, data=payload.encode(), headers=headers, retries=3)
    data = resp.json()
    return data.get("access_token", "0"), data.get("open_id", "0")

def create_jwt_sync(region: str):
    lock = region_locks[region]
    with lock:
        key = f"token:{region}"
        raw = cache_get(key)
        if raw:
            try:
                info = json.loads(raw)
                if time.time() < info.get("expires_at", 0):
                    return  # still valid
            except Exception:
                pass

        account = get_account_credentials(region)
        if not account:
            raise ValueError("No credentials configured for region")

        token_val, open_id = get_access_token_sync(account)
        body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
        proto_bytes = json_to_proto_sync(body, FreeFire_pb2.LoginReq())
        # AES encrypt
        try:
            payload = aes_cbc_encrypt_sync(MAIN_KEY, MAIN_IV, proto_bytes)
        except Exception as e:
            logger.exception("AES encryption failed for region %s: %s", region, e)
            raise

        url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
            'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream", 'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1", 'ReleaseVersion': RELEASEVERSION
        }
        resp = post_with_retries_sync(url, data=payload, headers=headers, retries=3)
        if not resp.content:
            raise RuntimeError("Empty response from MajorLogin")
        msg_json = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
        stored = {
            'token': f"Bearer {msg_json.get('token','0')}",
            'region': msg_json.get('lockRegion','0'),
            'server_url': msg_json.get('serverUrl','0'),
            'expires_at': time.time() + TOKEN_TTL - 30
        }
        cache_set(key, json.dumps(stored), TOKEN_TTL)
        logger.info("Created and cached token for %s", region)

def initialize_tokens_sync():
    for r in SUPPORTED_REGIONS:
        try:
            create_jwt_sync(r)
        except Exception as e:
            logger.warning("Failed to init token for %s: %s", r, e)

def refresh_tokens_background(interval: int = TOKEN_TTL):
    while True:
        try:
            logger.info("Refreshing tokens for all regions (background)")
            initialize_tokens_sync()
        except Exception as e:
            logger.exception("Background token refresh failed: %s", e)
        time.sleep(interval)

def get_token_info_sync(region: str) -> Tuple[str, str, str]:
    key = f"token:{region}"
    raw = cache_get(key)
    if raw:
        info = json.loads(raw)
        if time.time() < info.get("expires_at", 0):
            return info['token'], info['region'], info['server_url']
    create_jwt_sync(region)
    raw = cache_get(key)
    if not raw:
        raise RuntimeError("Failed to obtain token for region")
    info = json.loads(raw)
    return info['token'], info['region'], info['server_url']

# ---------- Helper: validate server_url to avoid SSRF (basic) ----------
def is_safe_host(url: str) -> bool:
    # basic check: only allow http(s) scheme and not local/private ip addresses
    try:
        parsed = httpx.URL(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.host
        # resolve host to ip and check not private
        ip = socket.gethostbyname(host)
        # private IP ranges
        if ip.startswith("10.") or ip.startswith("172.") or ip.startswith("192.168.") or ip.startswith("127."):
            return False
        return True
    except Exception:
        return False

# ---------- Main API logic ----------
def get_account_information_sync(uid: str, unk: str, region: str, endpoint: str) -> dict:
    region = (region or "").upper()
    if region not in SUPPORTED_REGIONS:
        raise ValueError(f"Unsupported region: {region}")

    if not uid.isdigit() or not (5 <= len(uid) <= 20):
        raise ValueError("Invalid UID format")

    # build proto payload
    payload = json_to_proto_sync(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt_sync(MAIN_KEY, MAIN_IV, payload)

    token, lock, server = get_token_info_sync(region)
    if not server:
        raise RuntimeError("No server URL returned from login")

    # protect against SSRF / local host
    if not is_safe_host(server):
        raise RuntimeError("Server URL appears unsafe")

    headers = {
        'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream", 'Expect': "100-continue",
        'Authorization': token, 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    resp = post_with_retries_sync(server + endpoint, data=data_enc, headers=headers, retries=3)
    if not resp.content:
        raise RuntimeError("Empty response from GetPlayerPersonalShow server")
    parsed = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))
    return parsed

def format_response(data: dict) -> dict:
    b = data.get("basicInfo", {}) or {}
    profile = data.get("profileInfo", {}) or {}
    clan = data.get("clanBasicInfo", {}) or {}
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

# ---------- Rate limiting (simple token bucket per IP) ----------
# stored in redis if available, otherwise in-memory
rate_buckets = {}  # ip -> (tokens, last_ts)
rate_lock = threading.Lock()

def allow_request(ip: str) -> bool:
    if not ip:
        return True
    now = time.time()
    # try redis-based limiter
    if redis_client:
        key = f"rl:{ip}"
        try:
            # use incr and expire as simple limiter per second
            current = redis_client.incr(key)
            if current == 1:
                redis_client.expire(key, 1)
            return current <= RATE_LIMIT_RPS
        except Exception as e:
            logger.warning("Redis rate limiter failed: %s", e)
            # fallback to memory
    # in-memory token bucket
    with rate_lock:
        bucket = rate_buckets.get(ip)
        if not bucket:
            rate_buckets[ip] = [RATE_LIMIT_BURST, now]
            return True
        tokens, last = bucket
        # refill
        refill = (now - last) * RATE_LIMIT_RPS
        tokens = min(RATE_LIMIT_BURST, tokens + refill)
        if tokens < 1:
            # update state
            rate_buckets[ip] = [tokens, now]
            return False
        tokens -= 1
        rate_buckets[ip] = [tokens, now]
        return True

# ---------- Decorators ----------
def json_endpoint(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ValueError as ve:
            logger.warning("Bad request: %s", ve)
            return jsonify({"error": str(ve)}), 400
        except httpx.HTTPStatusError as he:
            logger.warning("Upstream returned HTTP error: %s", he)
            return jsonify({"error": "Upstream service error"}), 502
        except Exception as e:
            logger.exception("Unhandled exception in endpoint: %s", e)
            return jsonify({"error": "Internal server error"}), 500
    return wrapper

# ---------- Routes ----------
@app.route("/player-info", methods=["GET"])
@json_endpoint
def route_player_info():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if not allow_request(ip):
        return jsonify({"error": "Rate limit exceeded"}), 429

    uid = request.args.get("uid", "").strip()
    region = request.args.get("region", "").strip().upper()

    if not uid or not region:
        return jsonify({"error": "Please provide UID and REGION."}), 400

    # synchronous execution (safe for Flask)
    data = get_account_information_sync(uid, "7", region, "/GetPlayerPersonalShow")
    return jsonify(format_response(data)), 200

@app.route("/refresh", methods=["GET", "POST"])
@json_endpoint
def route_refresh():
    # limited access: allow only local or requests with a secret header if set
    refresh_token = request.headers.get("X-REFRESH-TOKEN", "")
    admin_token = os.getenv("ADMIN_REFRESH_TOKEN", "")
    if admin_token and refresh_token != admin_token:
        return jsonify({"error": "Unauthorized"}), 401

    # run refresh in background quickly
    t = threading.Thread(target=initialize_tokens_sync, daemon=True)
    t.start()
    return jsonify({"message": "Refresh started"}), 202

# ---------- Startup: initialize tokens and background refresher ----------
def start_background_services():
    # initialize tokens once (best-effort)
    try:
        initialize_tokens_sync()
    except Exception as e:
        logger.warning("Initial token initialization failed: %s", e)

    # start background refresh thread
    t = threading.Thread(target=refresh_tokens_background, args=(TOKEN_TTL,), daemon=True)
    t.start()
    logger.info("Background token refresher started (interval=%ds)", TOKEN_TTL)

# ---------- Run app ----------
if __name__ == "__main__":
    # start background services before serving
    start_background_services()
    # Recommended to run behind Gunicorn or a process manager for production
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=(os.getenv("DEBUG", "0") == "1"))

# ---------- Notes for production ----------
# - Use Gunicorn with multiple workers (gevent or uvicorn workers) for high concurrency:
#   gunicorn -w 4 -k gthread -t 120 "app:app"
#   or: gunicorn -w 4 -k uvicorn.workers.UvicornWorker "app:app"
# - Provide valid MAIN_KEY_BASE64 and MAIN_IV_BASE64 (IV must decode to 16 bytes, key 16/24/32)
# - If you expect very high RPS, run multiple instances behind a load balancer and enable Redis for shared cache & rate-limit
# - Set ADMIN_REFRESH_TOKEN env var to protect the /refresh endpoint remotely
# - Monitor logs and tune INSTANCE_CONCURRENCY / Gunicorn workers
