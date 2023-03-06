phone = ''
# 你的手机号
password = ''
# 登录密码
deviceId = ''
# 设备id
import json, requests, base64, hashlib, time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto import Random
random_generator = Random.new().read
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad
import logging as log
def create_key_pair(size):
    rsa = RSA.generate(size, random_generator)
    private_key = str(rsa.export_key(), 'utf8')
    private_key = private_key.split('-\n')[1].split('\n-')[0]
    public_key = str(rsa.publickey().export_key(), 'utf8')
    public_key = public_key.split('-\n')[1].split('\n-')[0]
    return public_key, private_key
def rsa_decrypt(input_string, private_key):
    input_bytes = base64.b64decode(input_string)
    rsa_key = RSA.importKey("-----BEGIN RSA PRIVATE KEY-----\n" + private_key + "\n-----END RSA PRIVATE KEY-----")
    cipher = PKCS1_v1_5.new(rsa_key)
    return str(cipher.decrypt(input_bytes, random_generator), 'utf-8')
def des_3_encrypt(string, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv.encode("utf-8"))
    ct_bytes = cipher.encrypt(pad(string.encode('utf8'), DES3.block_size))
    ct = base64.b64encode(ct_bytes).decode('utf8')
    return ct
def object_encrypt(object_to_encrypt, key, iv="66666666"):
    return des_3_encrypt(json.dumps(object_to_encrypt), key, iv)
rsa_key = create_key_pair(1024)  # 生成RSA私钥
# 开始本地生成RSA私钥，通过post提交数据来交换公钥
def main():
    url = 'https://server.59wanmei.com/campus/cam_iface46/exchangeSecretkey.action'
    data = {'key': rsa_key[0]}
    header = {"Host": "server.59wanmei.com",
              "Connection": "Keep-Alive",
              "Content-Type": "application/text",
              "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 5.1.1; HD1910 Build/LMY49I)",
              "Content-Length": "237"}
    res = requests.post(url, json=data, headers=header)
    return1 = json.loads(rsa_decrypt(res.text, rsa_key[1]))  # 公钥解密post返回的数据
    token = return1["session"]
    if token == '':
        log.warning('交换公钥失败')
    else:
        appkey = return1['key'][:24]
        password_encrypt = [des_3_encrypt(i, appkey, '66666666') for i in password]  # 密码des3加密
        url = 'https://server.59wanmei.com/campus/cam_iface46/loginnew.action'
        data = {"appCode": "M002",
                "deviceId": deviceId,
                "netWork": "wifi",
                "password": password_encrypt,
                "qudao": "xiaomi",
                "requestMethod": "cam_iface46/loginnew.action",
                "shebeixinghao": "sailfish",
                "systemType": "android",
                "telephoneInfo": "8.1.0",
                "telephoneModel": "HD1910",
                "type": "1",
                "userName": phone,
                "wanxiaoVersion": 10565101}
        data = {"session": token,
                "data": object_encrypt(data, appkey)}
        header = {"campusSign": hashlib.sha256(json.dumps(data).encode('utf-8')).hexdigest(),
                  "Content-Type": "application/text",
                  "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 5.1.1; HD1910 Build/LMY49I)",
                  "Host": "server.59wanmei.com",
                  "Connection": "Keep-Alive",
                  "Content-Length": "728"}
        login_res = requests.post(url, data=json.dumps(data), headers=header).json()
        login_message = login_res['message_']
        if login_res['code_'] == '0':
            log.warning(phone + '|' + login_message)
            url = 'https://reportedh5.17wanxiao.com/sass/api/epmpics'
            message_data = {
                "businessType": "epmpics",
                "jsonData": {
                    "templateid": "pneumonia",  # 教师端pneumoniaTe
                    "token": token
                },
                "method": "userComeApp"}
            message_header = {
                "User-Agent": "Mozilla/5.0 (Linux; U; Android 10; zh-CN; IN2010 Build/QKQ1.191222.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/69.0.3497.100 UWS/3.22.2.38 Mobile Safari/537.36 UCBS/3.22.2.38_211216145512 NebulaSDK/1.8.100112 Nebula AlipayDefined(nt:4G,ws:411|0|2.625) AliApp(AP/10.2.53.7000) AlipayClient/10.2.53.7000 Language/zh-Hans useStatusBar/true isConcaveScreen/true Region/CNAriver/1.0.0 MiniProgram APXWebView",
                "Content-Type": "application/json;charset=UTF-8", "Host": "reportedh5.17wanxiao.com"}
            message_res = requests.post(url, json=message_data, headers=message_header).json()
            if message_res["code"] == "10000":
                data = json.loads(message_res["data"])
                message_dict = {
                    "areaStr": data['areaStr'],
                    "ver": data["ver"],
                    "deptStr": data['deptStr'],
                    "deptid": data['deptStr']['deptid'] if data['deptStr'] else None,
                    "customerid": data['customerid'],
                    "userid": data['userid'],
                    "username": data['username'],
                    "stuNo": data['stuNo'],
                    "phonenum": data["phonenum"],
                    "templateid": data["templateid"],
                    "updatainfo": [
                        {"propertyname": i["propertyname"], "value": i["value"]}
                        for i in data["cusTemplateRelations"]
                    ],
                    "updatainfo_detail": [
                        {
                            "propertyname": i["propertyname"],
                            "checkValues": i["checkValues"],
                            "description": i["decription"],
                            "value": i["value"],
                        }
                        for i in data["cusTemplateRelations"]
                    ],
                    "checkbox": [
                        {"description": i["decription"], "value": i["value"], "propertyname": i["propertyname"]}
                        for i in data["cusTemplateRelations"]
                    ],
                }
                message_return = '获取信息成功'
                log.warning(message_dict["username"] + '|' + message_return)
                one_check_data = {
                    "businessType": "epmpics",
                    "method": "submitUpInfo",
                    "jsonData": {
                        "deptStr": message_dict["deptStr"],
                        "areaStr": message_dict["areaStr"],
                        "reportdate": round(time.time() * 1000),
                        "customerid": message_dict["customerid"],
                        "deptid": message_dict['deptStr']['deptid'] if message_dict['deptStr'] else None,
                        "source": "app",
                        "templateid": message_dict["templateid"],
                        "stuNo": message_dict["stuNo"],
                        "username": message_dict["username"],
                        "phonenum": phone,
                        "userid": message_dict["userid"],
                        "updatainfo": message_dict["updatainfo"],
                        "gpsType": 1,
                        "ver": message_dict["ver"],
                        "token": token,
                    },
                }
                one_check_header = {
                    "User-Agent": "Mozilla/5.0 (Linux; U; Android 10; zh-CN; IN2010 Build/QKQ1.191222.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/69.0.3497.100 UWS/3.22.2.38 Mobile Safari/537.36 UCBS/3.22.2.38_211216145512 NebulaSDK/1.8.100112 Nebula AlipayDefined(nt:4G,ws:411|0|2.625) AliApp(AP/10.2.53.7000) AlipayClient/10.2.53.7000 Language/zh-Hans useStatusBar/true isConcaveScreen/true Region/CNAriver/1.0.0 MiniProgram APXWebView",
                    "Content-Type": "application/json;charset=UTF-8",
                    "Host": "reportedh5.17wanxiao.com"}
                one_check_res = requests.post(url, json=one_check_data, headers=one_check_header).json()
                if one_check_res["code"] == "10000":
                    check_message = message_dict["username"] + '|打卡成功'
                    log.warning(check_message)
                else:
                    check_message = message_dict["username"] + '|打卡失败|' + one_check_res["data"]
                    log.warning(check_message)
            else:
                message_return = '获取信息失败'
                log.warning(message_return)
        else:
            log.warning(phone + '|' + login_message)

if __name__ == '__main__':
    for i in range(10):
        main()