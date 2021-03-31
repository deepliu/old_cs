#!/usr/bin/env python
# -*- coding: UTF-8 -*-
'''=================================================
@Project -> File   ：BMOrderManage_2021-3-1 -> use_authorization
@IDE    ：PyCharm
@Author ：Json
@Date   ：2021-03-08 10:45
@Desc   ：这个主要是使用token，老版本只用一个函数就能获取验证信息。新版获取token则需要一个类，此文件对标老板的 CsCookies
    提供两种模式，一种从文本获取，二不从文本获取。

    2021-3-9 更新数据从数据库获取
    从文件整体上看此模块实例对象应该作为 csuser 的一个属性,但是获取token需要cs_user的属性，所以在这里反过来了,
=================================================='''
import sys
import base64
import time
import json
import os

from CS.cs_token.authorization_get import CsAuthorization
from CS.users.cs_user import CSUser
from utils.convert_path import convert_path
from utils.log import logger

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = convert_path(BASE_DIR)


class OAuthToken(object):
    def __init__(self, cs_info, tex_model=False):
        '''
            model : False 标识重新获取token，用于脚本每天处理订单。输入True，从文本避免多次请求token，使用场景，获取cs产品信息
            主要属性：token字符串
            token 的过期时间
            功能：
            获取最新token
            检测token是否过期哦
            token_expiry: datetime in UTC
        '''
        self.cs_info = cs_info
        self.cs_user_obj = CSUser(cs_info)  # cs_info 有可能是cs 用户编号，也有可能是我们系统的用户名
        self.customer_id = self.cs_user_obj.cs_user_num
        self.tex_model = tex_model
        self.exp_times_tamp = self.cs_user_obj.exp_times_tamp  # token的过期时间,时间戳形式，便于比较是否过期 ,
        self.token_time = self.cs_user_obj.exp_time  # token的过期时间,%Y-%m-%d %H:%M:%S"，便于直接看
        self.token_str = self.cs_user_obj.token  # token base64 编码的字符串
        self.init_token()  # 初始化token，从数据库读取，如果过期则重新获取

    def is_expired(self):
        # 每次使用token 需检查一下是否过期,比较时间戳
        time_difference = int(self.exp_times_tamp) - int(time.time())
        if int(self.exp_times_tamp) > int(time.time()) + 1000:  # 为了保险，将过期时间提前1000秒
            logger.info('token在{0}s 后过期'.format(time_difference))
            return True  # 未过期
        else:
            logger.info('重新获取token')
            self.get_token_complete()
            return False

    def parser_token(self, cs_token):
        """
        解析token，获取真实的过期时间，获取token的过期时间
        :return: 时间戳
        """
        token = cs_token[u'result'][u'token']
        token_str = token.split('.')[1]
        missing_padding = 4 - len(token_str) % 4
        if missing_padding:
            token_str += '=' * missing_padding
        base64_str = base64.b64decode(token_str)
        token_info = eval(base64_str)
        token_timestruct = token_info['exp']
        customerNo = token_info['customerNo']
        if customerNo == self.customer_id:
            time_obj = time.localtime(token_timestruct)  # 转成time.struct_time 对象，程序使用的对象，
            token_time = time.strftime("%Y-%m-%d %H:%M:%S", time_obj)
            logger.info('token过期时间{0}'.format(token_time))
            logger.info("信息一致")
            return token_timestruct, token_time, token  # 时间戳，明文时间，token base64加密字符串
        else:
            logger.error('用户信息错误')
            logger.error(base64_str)
            raise Exception('用户信息错误')

    def init_token(self):
        """
        从文本获取token，不够通用。改为从数据库获取
        :return:
        """
        if self.tex_model:
            if all([self.exp_times_tamp, self.token_time, self.token_str]):  # 检查从数据库获取的token信息，都为不为空，检查是否过期，否则重新获取
                self.is_expired()  # 检查token是否过期
            else:
                self.get_token_complete()
        else:
            self.get_token_complete()

    def get_token_complete(self):
        """
        从cs请求最新的token
        :return:
        """
        Token_obj = CsAuthorization(self.cs_user_obj, input_code=False)
        cs_token = Token_obj.get_access_token()  # json 形式
        if cs_token:
            self.exp_times_tamp, self.token_time, self.token_str = self.parser_token(cs_token)  # 每次获取token，重新获取过期时间
            self.cs_user_obj.add_token_to_sql(self.exp_times_tamp, self.token_time, self.token_str,
                                              self.customer_id)  # 将最新的token信息存到数据库
        else:
            raise Exception('获取token失败')


def init_version():
    """
    判断解释器版本，兼容2和3
    :return:
    """
    # PY2 = sys.version_info[0] == 2
    # PY3 = sys.version_info[0] == 3
    # print("PY2: %s, PY3: %s." % (str(PY2), str(PY3)))
    # print(sys.version_info)
    # print(sys.version_info < (3, 10))
    if sys.version_info < (3, 0):
        reload(sys)
        sys.setdefaultencoding('utf8')
        # print("current python version is less 3.10, current version: %s." % sys.version)


if __name__ == '__main__':
    init_version()
    oauth_token = OAuthToken('2119', tex_model=True)
    token_str = {'code': 200, 'msg': 'success', 'result': {'customerType': 'dropship', 'wholesale': 'HK', 'masterAccount': True, 'contactPerson': 'nancy', 'headPortrait': '', 'dropship': 'HK,US', 'customerNo': '2119', 'token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyZW1lbWJlciI6InRydWUiLCJ1aWQiOiIxNzA0MiIsIndob2xlc2FsZSI6IkhLIiwiZXhwIjoxNjE1ODkyNTI3LCJpYXQiOjE2MTU4ODE3MjcsImp0aSI6IjAwODRjYTI3MDM1NTRlMjU4MjIyZTUxOTMxOTJjNGUxIiwiZHJvcHNoaXAiOiJISyxVUyIsImN1c3RvbWVyTm8iOiIyMTE5IiwiZ3JvdXAiOiJjdXN0b21lciIsInVzZXJuYW1lIjoibmFuY3kifQ.PzQUhayz06hWAvwmAOnDUK3jVjQyM90z8MFwzRz9Wsc'}}

    oauth_token.parser_token(token_str)
    # for i in range(5):
    #     time.sleep(1)
    #     oauth_token.is_expired()
