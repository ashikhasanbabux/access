from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
import my_pb2
import output_pb2
import jwt
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

# Define platform types
PLATFORM_TYPES = {
    "apple": 10,
    "facebook": 3,
    "google": 8,
    "guest": 4,
    "vk": 5,
    "huawei": 7,
    "x": 11
}

def encrypt_message(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def try_platforms(access_token, open_id):
    """Try all platform types to get a valid token."""
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB49"
    }

    for platform_name, platform_type in PLATFORM_TYPES.items():
        game_data = my_pb2.GameData()
        game_data.timestamp = "2024-12-05 18:15:32"
        game_data.game_name = "free fire"
        game_data.game_version = 1
        game_data.version_code = "1.108.3"
        game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
        game_data.device_type = "Handheld"
        game_data.network_provider = "Verizon Wireless"
        game_data.connection_type = "WIFI"
        game_data.screen_width = 1280
        game_data.screen_height = 960
        game_data.dpi = "240"
        game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
        game_data.total_ram = 5951
        game_data.gpu_name = "Adreno (TM) 640"
        game_data.gpu_version = "OpenGL ES 3.0"
        game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
        game_data.ip_address = "172.190.111.97"
        game_data.language = "en"
        game_data.open_id = open_id
        game_data.access_token = access_token
        game_data.platform_type = platform_type
        game_data.field_99 = str(platform_type)
        game_data.field_100 = str(platform_type)

        serialized_data = game_data.SerializeToString()
        encrypted_data = encrypt_message(serialized_data)
        hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')
        edata = bytes.fromhex(hex_encrypted_data)

        try:
            response = requests.post(url, data=edata, headers=headers, verify=False, timeout=5)
            if response.status_code == 200:
                try:
                    example_msg = output_pb2.Garena_420()
                    example_msg.ParseFromString(response.content)
                    data_dict = {field.name: getattr(example_msg, field.name)
                                 for field in example_msg.DESCRIPTOR.fields
                                 if field.name not in ["binary", "binary_data", "Garena420"]}
                    if data_dict and "token" in data_dict:
                        token_value = data_dict["token"]
                        try:
                            decoded_token = jwt.decode(token_value, options={"verify_signature": False})
                        except Exception as e:
                            decoded_token = {"error": str(e)}
                        return {
                            "server": data_dict.get("region", "N/A"),
                            "uid": data_dict.get("account_id", "N/A"),
                            "token": token_value
                        }
                except Exception:
                    try:
                        data_dict = response.json()
                        if "token" in data_dict:
                            return {
                                "server": data_dict.get("region", "N/A"),
                                "uid": data_dict.get("account_id", "N/A"),
                                "token": data_dict["token"]
                            }
                    except ValueError:
                        continue
        except requests.RequestException as e:
            logger.error(f"Request to MajorLogin failed for platform {platform_name}: {str(e)}")
            continue
    return None

@app.route('/guest', methods=['GET'])
def guest():
    uid = request.args.get('uid')
    password = request.args.get('password')
    if not uid or not password:
        return jsonify({"message": "Missing uid or password"}), 400

    oauth_url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    payload = {
        'uid': uid,
        'password': password,
        'response_type': "token",
        'client_type': "2",
        'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        'client_id': "100067"
    }
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip"
    }

    try:
        oauth_response = requests.post(oauth_url, data=payload, headers=headers, timeout=5)
        logger.debug(f"OAuth response status: {oauth_response.status_code}, content: {oauth_response.text}")
        if oauth_response.status_code != 200:
            try:
                return jsonify(oauth_response.json()), oauth_response.status_code
            except ValueError:
                return jsonify({"message": oauth_response.text}), oauth_response.status_code

        oauth_data = oauth_response.json()
        if 'access_token' not in oauth_data or 'open_id' not in oauth_data:
            return jsonify({"message": "OAuth response missing access_token or open_id"}), 500

        access_token = oauth_data['access_token']
        open_id = oauth_data['open_id']
        result = try_platforms(access_token, open_id)
        if result:
            return jsonify(result), 200
        return jsonify({"message": "No valid token found for any platform"}), 500

    except requests.RequestException as e:
        logger.error(f"OAuth request failed: {str(e)}")
        return jsonify({"message": str(e)}), 500

@app.route('/main', methods=['GET'])
def main():
    access_token = request.args.get('access_token')
    if not access_token:
        return jsonify({"message": "Missing access_token"}), 400

    # Fetch open_id using access_token
    try:
        uid_url = "https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/"
        uid_headers = {
            "authority": "prod-api.reward.ff.garena.com",
            "accept": "application/json, text/plain, */*",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
            "access-token": access_token,
            "origin": "https://reward.ff.garena.com",
            "referer": "https://reward.ff.garena.com/",
            "sec-ch-ua": '"Not.A/Brand";v="99", "Chromium";v="124"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Android"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        }
        uid_res = requests.get(uid_url, headers=uid_headers)
        logger.debug(f"UID response status: {uid_res.status_code}, content: {uid_res.text}")
        try:
            uid_data = uid_res.json()
        except ValueError:
            logger.error(f"UID response is not JSON: {uid_res.text}")
            return jsonify({"message": "Invalid JSON response from inspect_token"}), 500

        uid = uid_data.get("uid")
        if not uid:
            logger.error(f"No UID found in response: {uid_data}")
            return jsonify({"message": "Failed to extract UID"}), 400

        openid_url = "https://shop2game.com/api/auth/player_id_login"
        openid_headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "ar-MA,ar;q=0.9,en-US;q=0.8,en;q=0.7,ar-AE;q=0.6,fr-FR;q=0.5,fr;q=0.4",
            "Connection": "keep-alive",
            "Content-Type": "application/json",
            "Origin": "https://shop2game.com",
            "Referer": "https://shop2game.com/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36",
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"'
        }
        payload = {"app_id": 100067, "login_id": str(uid)}
        openid_res = requests.post(openid_url, headers=openid_headers, json=payload)
        logger.debug(f"OpenID response status: {openid_res.status_code}, content: {openid_res.text}")
        try:
            openid_data = openid_res.json()
        except ValueError:
            logger.error(f"OpenID response is not JSON: {openid_res.text}")
            return jsonify({"message": "Invalid JSON response from player_id_login"}), 500

        open_id = openid_data.get("open_id")
        if not open_id:
            logger.error(f"No open_id found in response: {openid_data}")
            return jsonify({"message": "Failed to extract open_id"}), 500

        result = try_platforms(access_token, open_id)
        if result:
            return jsonify(result), 200
        return jsonify({"message": "No valid token found for any platform"}), 500

    except requests.RequestException as e:
        logger.error(f"Request failed: {str(e)}")
        return jsonify({"message": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1080, debug=True)
