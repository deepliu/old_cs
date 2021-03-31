# -*- coding: utf-8 -*-
'''=================================================
@Project -> File   ：BMOrderManage_2021-3-1 -> use_authorization
@IDE    ：PyCharm
@Author ：Json
@Date   ：2021-03-08 10:45
@Desc   ：这个主要是获取token，老版本只用一个函数就能获取验证信息。新版获取token则需要一个类，此文件对标老板的 get_cookie
=================================================='''
import base64
import datetime
import json
import sys

import requests
import os

from retry.api import retry_call

from CS.cs_token.skip_vscode_2.skip_code import SkipCode
from utils.convert_path import convert_path
from utils.log import logger

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = convert_path(BASE_DIR)
# print(BASE_DIR)
token_file_path = os.path.join(BASE_DIR, 'token_file')


class CsAuthorization:
    def __init__(self, cs_user_obj, input_code=False, save_code=True):
        self.cs_user_obj = cs_user_obj
        self.input_code = input_code  # 为True，手动输入
        self.save_code = save_code
        self.customer_id = self.cs_user_obj.cs_user_num
        self.headers = {
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json;charset=UTF-8',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36'
        }
        self.url = 'https://api.cameronsino.com/b2d/api/account/login'
        self.codeKey, self.image_base64 = self.request_code()
        self.image_code = self.get_image_code()
        self.dict = self.get_data_dict()

        self.start = datetime.datetime.now()
        self.expired_time = 6000  # 过期时间6000秒，超过6000秒重新获取cookie

    def request_code(self):
        """
        :return: {
        "code": 200,
        "msg": "success",
        "result": {
        "codeKey": "security.e115baea-8b62-4901-9038-cfb79623d169",
        "image": "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"
                }
            }
        """
        code_url = 'https://api.cameronsino.com/b2d/api/account/security-code?lang=en_us'
        try:
            respone_json = retry_call(self.make_request_get, fargs=[code_url], tries=1, delay=20)
            respone_code = respone_json.get('code')
            msg = respone_json.get('msg')
            result = respone_json.get('result')
            if respone_code == 200 and msg == 'success':
                codeKey = result.get('codeKey')
                imge_base64 = result.get('image')
                return codeKey, imge_base64
            else:
                return None, None
        except Exception as e:
            logger.error('获取验证码失败')
            logger.error(e)
            raise Exception("获取验证码失败")

    @staticmethod
    def save_image_code(b64_data):
        # 将base64 转为图片存入本地,便于手动输入
        image_path = os.path.join(BASE_DIR, 'skip_vscode_2/code_image/temp.png')
        image_path = convert_path(image_path)
        data = base64.b64decode(b64_data)  # 解码成明文
        with open(image_path, 'wb') as f:
            f.write(data)
        return image_path

    def get_image_code(self):
        skipcode = SkipCode()
        try:
            if self.image_base64:
                if self.save_code:
                    image_path = self.save_image_code(self.image_base64)  # 保存验证码
                    if self.input_code:
                        import matplotlib.pyplot as plt  # plt 用于显示图片
                        import matplotlib.image as mpimg  # mpimg 用于读取图片
                        lena = mpimg.imread(image_path)  # 读取和代码处于同一目录下的 lena.png
                        plt.imshow(lena)  # 显示图片
                        plt.axis('off')  # 不显示坐标轴
                        plt.show()
                        code = input("查看验证码，手动输入code:")
                    else:
                        code = skipcode.get_code(self.image_base64)
                else:
                    code = skipcode.get_code(self.image_base64)
            else:
                code = None
        except Exception as e:
            logger.error('识别code异常')
            code = None
        return code

    def get_data_dict(self):
        """
        输入参数
        {lang: "en_us"
        password: "bomi001"
        remember: true
        securityCode: "ZST3"
        securityCodeKey: "security.4065e618-525a-4220-b24e-50ee76245fbb"
        username: "nancy"}
        :return:
        """
        if self.image_code:
            data_dict = {"username": self.cs_user_obj.cs_user_name,
                         "password": self.cs_user_obj.cs_password,
                         "remember": True,
                         "securityCodeKey": self.codeKey,
                         "securityCode": self.image_code,
                         "lang": "en_us"}

            # data_dict = {'username': u'Nancy', 'lang': 'en_us', 'remember': True, 'securityCode': u'bfv8',
            #  'securityCodeKey': u'security.22ab8d47-99a6-46fa-9e14-8c1905b40a4e', 'password': u'bomi001'}

            logger.info(data_dict)
            return data_dict
        else:
            raise Exception('验证马识别异常')

    def make_request_get(self, code_url):  # 为了解决 Max retries exceeded with url:的错误
        req = requests.get(code_url, headers=self.headers, timeout=15)
        return req.json()

    def make_request(self):  # 为了解决 Max retries exceeded with url:的错误
        logger.info('开始用户: {0} 的cookie'.format(self.cs_user_obj.cs_user_name))
        req = requests.post(self.url, data=json.dumps(self.dict), headers=self.headers, timeout=10)
        logger.info('获取用户: {0} 的cookie'.format(self.cs_user_obj.cs_user_name))
        logger.info(req.json())
        return req.json()

    def get_access_token(self):
        """
        error info :
        {u'msg': u'\u6ca1\u6709\u643a\u5e26lang\u6216region\u53c2\u6570', u'code': 500, u'result': None}
        success info :
        {
        code: 200
        msg: "success"
        result: {customerType: "dropship", wholesale: "HK", masterAccount: true, contactPerson: "nancy",…}
        contactPerson: "nancy"
        customerNo: "2119"
        customerType: "dropship"
        dropship: "HK,US"
        headPortrait: ""
        masterAccount: true
        token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyZW1lbWJlciI6InRydWUiLCJ1aWQiOiIxNzA0MiIsIndob2xlc2FsZSI6IkhLIiwiZXhwIjoxNjE0OTQ2NzY2LCJpYXQiOjE2MTQ5MzU5NjYsImp0aSI6IjNhNDljYTQxMjM4ZjQ3MDBiZTVlYWJlNDQyYjJiYmQ4IiwiZHJvcHNoaXAiOiJISyxVUyIsImN1c3RvbWVyTm8iOiIyMTE5IiwiZ3JvdXAiOiJjdXN0b21lciIsInVzZXJuYW1lIjoibmFuY3kifQ.K7voIwwWU3gdHW5nHHEdeQ494v92U1pYKobxhplSt0Y"
        wholesale: "HK"
        }

        """
        logger.info("Trying to get a new user access cs_token.json ... ")
        try:
            resp = retry_call(self.make_request, tries=2, delay=2)  # 重试2次
            if resp['code'] == 200:
                token_file_name = self.customer_id + '.json'
                token_file_name_path = os.path.join(token_file_path, token_file_name)
                json.dump(resp, open(token_file_name_path, mode='w'))  # 记录token到文本流
                return resp
            else:
                return None
        except:
            logger.error('异常 user access cs_token.json 请求2次，状态依然错误')
            return None


# COOKIES = get_cs_cookies()

if __name__ == '__main__':
    reload(sys)
    sys.setdefaultencoding('utf8')
    Token_obj = CsAuthorization('2119', input_code=False)
    cs_token = Token_obj.get_access_token()
    # print(cs_token.json)
