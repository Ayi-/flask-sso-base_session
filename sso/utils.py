# -*- coding: utf-8 -*-
"""
    sso.util
    ~~~~~~~~~

    本模块实现各种功能处理

    :copyright: (c) 2015 by Eli.
    :license: MIT, see LICENSE for more details.
"""
import jwt

def getCookieTokenInfo(cookie_token):
    """从cookie_token中获取信息

    :param cookie_token:
    :return:
    """
    info = jwt.decode(cookie_token,'sso',algorithms=['HS256'])
    return info

def checkCookieToken(request,token_list):
    cookie_token = request.headers.get('Authorization', None)
    if cookie_token:
        info = getCookieTokenInfo(cookie_token)
        if info:
            sid = token_list.get(cookie_token,None)
            if sid:
                return sid
    return False