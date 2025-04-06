from flask import Flask, jsonify, request
import requests
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from protobuf_decoder.protobuf_decoder import Parser
from datetime import datetime
import json

app = Flask(__name__)

# FF INFO ACC 
DEFAULT_UID = "3197059560"
DEFAULT_PASS = "3EC146CD4EEF7A640F2967B06D7F4413BD4FB37382E0ED260E214E8BACD96734"
JWT_GEN_URL = "https://aditya-jwt-token-generate.vercel.app/token"

# GET JWT
def get_jwt():
    try:
        url = f"{JWT_GEN_URL}?uid={DEFAULT_UID}&password={DEFAULT_PASS}"
        response = requests.get(url)
        if response.status_code == 200:
            jwt_data = response.json()
            return jwt_data.get("JWT TOKEN")  # or "token" based on actual key
        return None
    except Exception as e:
        return None

# DO NOT EDIT
def Encrypt_ID(x):
    x = int(x)
    dec = ['{:02x}'.format(i) for i in range(128, 256)]
    xxx = ['{:02x}'.format(i) for i in range(1, 128)]
    x = x / 128
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                strx = int(x)
                y = (x - strx) * 128
                z = (y - int(y)) * 128
                n = (z - int(z)) * 128
                m = (n - int(n)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                strx = int(x)
                y = (x - strx) * 128
                z = (y - int(y)) * 128
                n = (z - int(z)) * 128
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {'wire_type': result.wire_type}
        if result.wire_type in ["varint", "string"]:
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def get_available_room(input_text):
    parsed_results = Parser().parse(input_text)
    parsed_results_dict = parse_results(parsed_results)
    return json.dumps(parsed_results_dict)

@app.route('/api/player-info', methods=['GET'])
def get_player_info():
    try:
        player_id = request.args.get('id')
        if not player_id:
            return jsonify({
                "status": "error",
                "message": "Player ID is required",
                "credits": "GMG-ID-INFO",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 400

        jwt_token = get_jwt()
        if not jwt_token:
            return jsonify({
                "status": "error",
                "message": "Failed to generate JWT token",
                "credits": "GMG-ID-INFO",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 500

        data = bytes.fromhex(encrypt_api(f"08{Encrypt_ID(player_id)}1007"))
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB48',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Authorization': f'Bearer {jwt_token}',
            'Content-Length': '16',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'clientbp.ggblueshark.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }

        response = requests.post(url, headers=headers, data=data, verify=False)

        if response.status_code == 200:
            hex_response = binascii.hexlify(response.content).decode('utf-8')
            json_result = get_available_room(hex_response)
            parsed_data = json.loads(json_result)

            try:
                player_data = {
                    "basic_info": {
                        "name": parsed_data["1"]["data"]["3"]["data"],
                        "id": player_id,
                        "likes": parsed_data["1"]["data"]["21"]["data"],
                        "level": parsed_data["1"]["data"]["6"]["data"],
                        "server": parsed_data["1"]["data"]["5"]["data"],
                        "bio": parsed_data["9"]["data"]["9"]["data"],
                        "booyah_pass_level": parsed_data["1"]["data"]["18"]["data"],
                        "account_created": datetime.fromtimestamp(parsed_data["1"]["data"]["44"]["data"]).strftime("%Y-%m-%d %H:%M:%S")
                    }
                }

                try:
                    player_data["animal"] = {
                        "name": parsed_data["8"]["data"]["2"]["data"]
                    }
                except:
                    player_data["animal"] = None

                try:
                    player_data["Guild"] = {
                        "name": parsed_data["6"]["data"]["2"]["data"],
                        "id": parsed_data["6"]["data"]["1"]["data"],
                        "level": parsed_data["6"]["data"]["4"]["data"],
                        "members_count": parsed_data["6"]["data"]["6"]["data"],
                        "leader": {
                            "id": parsed_data["6"]["data"]["3"]["data"],
                            "name": parsed_data["7"]["data"]["3"]["data"],
                            "level": parsed_data["7"]["data"]["6"]["data"],
                            "booyah_pass_level": parsed_data["7"]["data"]["18"]["data"],
                            "likes": parsed_data["7"]["data"]["21"]["data"],
                            "account_created": datetime.fromtimestamp(parsed_data["7"]["data"]["44"]["data"]).strftime("%Y-%m-%d %H:%M:%S")
                        }
                    }
                except:
                    player_data["Guild"] = None

                return jsonify({
                    "status": "success",
                    "message": "Player information retrieved successfully",
                    "data": player_data,
                    "credits": "GMG-ID-INFO",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })

            except Exception as e:
                return jsonify({
                    "status": "error",
                    "message": f"Failed to parse player information: {str(e)}",
                    "credits": "GMG-ID-INFO",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }), 500

        return jsonify({
            "status": "error",
            "message": f"API request failed with status code: {response.status_code}",
            "credits": "GMG-ID-INFO",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), response.status_code

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"An unexpected error occurred: {str(e)}",
            "credits": "GMGIDINFO",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
    
