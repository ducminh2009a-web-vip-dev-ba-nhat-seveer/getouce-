import json
import base64
import asyncio
import httpx
from flask import Flask, request, jsonify
import logging
from google.protobuf import json_format
import sys
import random

try:
    from Crypto.Cipher import AES
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError(
        "Missing dependency: pycryptodome. Install with: pip install -r requirements.txt"
    ) from exc

# Configure logging for Vercel / local server
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Attempt to import Protobuf
try:
    from proto import FreeFire_pb2, AccountPersonalShow_pb2
    logger.info("Successfully imported Protobuf modules")
except ImportError as e:
    logger.error(f"Failed to import Protobuf modules: {e}")
    raise ImportError("Ensure Protobuf files are in the proto/ directory.") from e

# === Settings ===
MAIN_KEY = base64.b64decode("WWcmdGMlREV1aDYlWmNeOA==")
MAIN_IV = base64.b64decode("Nm95WkRyMjJFM3ljaGpNJQ==")
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
RELEASEVERSION = "OB53"

app = Flask(__name__)

REGION_SERVERS = {
    "IND": "https://client.ind.freefiremobile.com",
    "ME": "https://clientbp.ggpolarbear.com",
    "VN": "https://clientbp.ggpolarbear.com",
    "BD": "https://clientbp.ggpolarbear.com",
    "PK": "https://clientbp.ggpolarbear.com",
    "SG": "https://clientbp.ggpolarbear.com",
    "BR": "https://client.us.freefiremobile.com",
    "NA": "https://client.us.freefiremobile.com",
    "ID": "https://clientbp.ggpolarbear.com",
    "RU": "https://clientbp.ggpolarbear.com",
    "TH": "https://clientbp.ggpolarbear.com",
}

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    try:
        aes = AES.new(key, AES.MODE_CBC, iv)
        decrypted = aes.decrypt(ciphertext)
        if not decrypted:
            return decrypted
        padding_length = decrypted[-1]
        if 1 <= padding_length <= AES.block_size:
            return decrypted[:-padding_length]
        return decrypted
    except Exception as e:
        logger.warning(f"AES decryption failed, returning raw data: {e}")
        return ciphertext


async def json_to_proto(json_data: dict, proto_message) -> bytes:
    json_format.ParseDict(json_data, proto_message, ignore_unknown_fields=True)
    return proto_message.SerializeToString()


def decode_jwt_payload(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        payload_json = base64.urlsafe_b64decode(payload_b64).decode("utf-8")
        return json.loads(payload_json)
    except Exception as e:
        logger.warning(f"Failed to decode JWT payload: {e}")
        return {}


def encode_varint(value: int) -> bytes:
    if value <= 0:
        return b"\x00"
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value & 0x7F)
    return bytes(out)


def to_int(value, default=0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def clean_name(value) -> str:
    if value is None:
        return "Unknown"
    value = str(value).replace("\x00", "").strip()
    return value or "Unknown"


def try_decrypt_nickname(value: str) -> str:
    """Return readable nickname. If it is not valid encrypted base64, return the original text."""
    raw = clean_name(value)
    if raw == "Unknown":
        return raw
    try:
        encrypted_bytes = base64.b64decode(raw, validate=True)
        if len(encrypted_bytes) % AES.block_size != 0:
            return raw
        decrypted = aes_cbc_decrypt(MAIN_KEY, MAIN_IV, encrypted_bytes)
        nickname = decrypted.decode("utf-8", errors="ignore").strip()
        return nickname or raw
    except Exception:
        return raw


def get_request_arg(name: str):
    if request.is_json:
        body = request.get_json(silent=True) or {}
        if name in body:
            return body.get(name)
    return request.args.get(name) or request.form.get(name)


async def get_access_token(uid: str, password: str):
    """Get the access token for the provided account credentials."""
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    form_data = {
        "uid": str(uid),
        "password": str(password),
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067",
    }
    headers = {
        "User-Agent": USERAGENT,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        logger.info("Sending access token request")
        resp = await client.post(url, data=form_data, headers=headers)
        raw_text = resp.text
        resp.raise_for_status()
        try:
            data = resp.json()
        except ValueError as exc:
            raise RuntimeError(f"Access endpoint returned non-JSON response: {raw_text[:200]}") from exc

    access_token = data.get("access_token") or data.get("token") or "0"
    open_id = data.get("open_id") or data.get("openid") or "0"
    if access_token == "0" or open_id == "0":
        raise RuntimeError(f"Access token not found in response: {data}")
    return access_token, open_id


async def get_player_info(account_id: int, token: str, server_url: str = None, region: str = None):
    if not account_id or not token or token == "0":
        return 0, "Unknown"

    proto_bytes = b"\x08" + encode_varint(account_id) + b"\x10\x07"
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

    urls = []
    if region and region.upper() in REGION_SERVERS:
        urls.append(f"{REGION_SERVERS[region.upper()]}/GetPlayerPersonalShow")
    if server_url and server_url != "0":
        urls.append(f"{server_url.rstrip('/')}/GetPlayerPersonalShow")
    urls.extend([
        "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
    ])
    urls = list(dict.fromkeys(urls))

    random_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
    headers = {
        "User-Agent": USERAGENT,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Authorization": f"Bearer {token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-Forwarded-For": random_ip,
        "X-GA": "v1 1",
        "ReleaseVersion": RELEASEVERSION,
    }

    async with httpx.AsyncClient(timeout=12.0, verify=False) as client:
        for url in urls:
            try:
                logger.info(f"Trying PlayerShow on {url}")
                resp = await client.post(url, data=payload, headers=headers)
                if resp.status_code != 200:
                    logger.warning(f"PlayerShow failed {resp.status_code} on {url}: {resp.text[:120]}")
                    continue

                res_msg = AccountPersonalShow_pb2.AccountPersonalShowInfo()
                res_msg.ParseFromString(resp.content)
                res_dict = json_format.MessageToDict(
                    res_msg,
                    preserving_proto_field_name=True,
                    always_print_fields_with_no_presence=False,
                )
                basic_info = res_dict.get("basic_info") or {}
                level = to_int(basic_info.get("level"), 0)
                nickname = clean_name(
                    basic_info.get("nickname")
                    or basic_info.get("external_name")
                    or basic_info.get("clan_name")
                )
                return level, nickname
            except Exception as e:
                logger.warning(f"Error connecting/parsing PlayerShow on {url}: {e}")
                continue

    return 0, "Unknown"


async def create_jwt(uid: str, password: str):
    token_val, open_id = await get_access_token(uid, password)
    login_body = {
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": token_val,
        "orign_platform_type": "4",
    }
    proto_bytes = await json_to_proto(login_body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

    url = "https://loginbp.ggpolarbear.com/MajorLogin"
    headers = {
        "User-Agent": USERAGENT,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "X-Unity-Version": "2022.3.47f1",
        "X-GA": "v1 1",
        "ReleaseVersion": RELEASEVERSION,
    }
    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        logger.info("Sending MajorLogin request")
        resp = await client.post(url, data=payload, headers=headers)
        resp.raise_for_status()

    login_res = FreeFire_pb2.LoginRes.FromString(resp.content)
    msg = json_format.MessageToDict(login_res, preserving_proto_field_name=True)

    token = msg.get("token") or "0"
    server_url = msg.get("server_url") or "0"
    region = msg.get("lock_region") or msg.get("noti_region") or "VN"
    account_id = to_int(msg.get("account_id"), 0)

    payload_data = decode_jwt_payload(token) if token != "0" else {}
    if not account_id:
        account_id = to_int(payload_data.get("account_id") or payload_data.get("accountId"), 0)

    jwt_nickname = try_decrypt_nickname(payload_data.get("nickname", "Unknown"))
    target_server = server_url if server_url.startswith("http") else REGION_SERVERS.get(region, "https://clientbp.ggpolarbear.com")
    level, nickname = await get_player_info(account_id, token, target_server, region)
    if nickname == "Unknown":
        nickname = jwt_nickname

    return {
        "token": token,
        "access_token": token_val,
        "open_id": open_id,
        "uid": account_id or str(uid),
        "level": level,
        "name": nickname,
        "nickname": nickname,
        "region": region,
        "server_url": target_server,
    }


@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "API is running", "version": RELEASEVERSION}), 200


@app.route("/access", methods=["GET", "POST"])
def access_only():
    try:
        uid = get_request_arg("uid")
        password = get_request_arg("password")
        if not uid or not password:
            return jsonify({"error": "Please provide both uid and password."}), 400
        access_token, open_id = asyncio.run(get_access_token(uid, password))
        return jsonify({"access_token": access_token, "open_id": open_id}), 200
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error in /access: {e.response.status_code} {e.response.text[:200]}")
        return jsonify({"error": f"Access failed with HTTP {e.response.status_code}"}), 502
    except Exception as e:
        logger.error(f"Error in /access: {e}")
        return jsonify({"error": f"Failed: {str(e)}"}), 500


@app.route("/token", methods=["GET", "POST"])
def get_jwt():
    try:
        uid = get_request_arg("uid")
        password = get_request_arg("password")
        if not uid or not password:
            return jsonify({"error": "Please provide both uid and password."}), 400
        result = asyncio.run(create_jwt(uid, password))
        return jsonify(result), 200
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error in /token: {e.response.status_code} {e.response.text[:200]}")
        return jsonify({"error": f"Login failed with HTTP {e.response.status_code}"}), 502
    except Exception as e:
        logger.error(f"Error in /token: {e}")
        return jsonify({"error": f"Failed: {str(e)}"}), 500


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    app.run(host="0.0.0.0", port=port, debug=True)
