import asyncio
import time
import httpx
import json
from collections import defaultdict
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64
import logging

# === Logging Setup ===
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FreeFireAPI")

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB50"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=200, ttl=300)  # زيادة الحجم لتحمل عدد أكبر من المستخدمين
cached_tokens = defaultdict(dict)

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: Message) -> Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    creds = {
        "IND": "uid=3947622285&password=92AAF030CF53C1DD509C3C6070BC79004C64A819F34AB8E07BD0ABCDC424D511",
        "BD": "uid=3957595605&password=7203510AB3D87E06CE54FC93ABE40D48AA6AEA55E2DEA2D2AA3487CBB20650D7",
        "BR": "uid=3788023112&password=5356B7495AC2AD04C0A483CF234D6E56FB29080AC2461DD51E0544F8D455CC24",
        "US": "uid=3788023112&password=5356B7495AC2AD04C0A483CF234D6E56FB29080AC2461DD51E0544F8D455CC24",
        "SAC": "uid=3788023112&password=5356B7495AC2AD04C0A483CF234D6E56FB29080AC2461DD51E0544F8D455CC24",
        "NA": "uid=4167202140&password=7F6CDF48F387A1D78010CB3359A3660BCFC5AA0040A0118D0287122973DD1FE3"
    }
    return creds.get(region.upper(), "uid=4167202140&password=7F6CDF48F387A1D78010CB3359A3660BCFC5AA0040A0118D0287122973DD1FE3")

# === Token Generation & Management ===
async def get_access_token(account: str):
    try:
        url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
        payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
        headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(url, data=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return data.get("access_token", "0"), data.get("open_id", "0")
    except Exception as e:
        logger.error(f"Failed to get access token: {e}")
        return "0", "0"

async def create_jwt(region: str):
    account = get_account_credentials(region)
    token_val, open_id = await get_access_token(account)
    if token_val == "0":
        logger.warning(f"Skipping region {region} due to failed token fetch")
        return
    body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream", 'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1", 'ReleaseVersion': RELEASEVERSION
    }
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(url, data=payload, headers=headers)
            resp.raise_for_status()
            msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
            cached_tokens[region] = {
                'token': f"Bearer {msg.get('token','0')}",
                'region': msg.get('lockRegion','0'),
                'server_url': msg.get('serverUrl','0'),
                'expires_at': time.time() + 25200
            }
            logger.info(f"Token cached for region {region}")
    except Exception as e:
        logger.error(f"Failed to create JWT for {region}: {e}")

async def initialize_tokens():
    tasks = [create_jwt(r) for r in SUPPORTED_REGIONS]
    await asyncio.gather(*tasks)

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)
        await initialize_tokens()

async def get_token_info(region: str) -> Tuple[str, str, str]:
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    await create_jwt(region)
    info = cached_tokens.get(region, {'token': "0", 'region': "0", 'server_url': "0"})
    return info['token'], info['region'], info['server_url']

# === Player Info Fetching ===
async def GetAccountInformation(uid, unk, region, endpoint):
    region = region.upper()
    if region not in SUPPORTED_REGIONS:
        raise ValueError(f"Unsupported region: {region}")
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token_info(region)
    if token == "0":
        raise ConnectionError(f"Unable to fetch token for region {region}")
    headers = {
        'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream", 'Expect': "100-continue",
        'Authorization': token, 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.post(server + endpoint, data=data_enc, headers=headers)
        resp.raise_for_status()
        return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))

# === API Routes ===
@app.route('/player-info')
async def get_account_info():
    region = request.args.get('region')
    uid = request.args.get('uid')
    if not uid or not region:
        return jsonify({"error": "Please provide UID and REGION."}), 400
    try:
        return_data = await GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow")
        return jsonify(format_response(return_data)), 200
    except Exception as e:
        logger.exception(f"Error fetching account info: {e}")
        return jsonify({"error": "Failed to fetch account info. Check UID/Region or try again later."}), 500

@app.route('/refresh', methods=['GET', 'POST'])
async def refresh_tokens_endpoint():
    try:
        await initialize_tokens()
        return jsonify({'message': 'Tokens refreshed for all regions.'}), 200
    except Exception as e:
        logger.exception(f"Error refreshing tokens: {e}")
        return jsonify({'error': f'Refresh failed: {e}'}), 500

# === Startup ===
async def startup():
    await initialize_tokens()
    asyncio.create_task(refresh_tokens_periodically())

if __name__ == '__main__':
    asyncio.run(startup())
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
