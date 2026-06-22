import hashlib
import json
import pickle

import redis
import requests
import time
from jwt import decode
from apiAnalysis import redis_pool
from apiAnalysis.conf.conf import *
from apiAnalysis.common.util import gen_banner
from apiAnalysis.db.collection import *
from apiAnalysis.model.exception import LibException, ParserException, AccountException
from apiAnalysis.model.model import HeaderModel, BodyModel, requests_request, AuthSession

def verify_session(account: SsoAccount, sso: WorkspaceSso):
    ts = WorkspaceAuth.objects(ws_id=sso.ws_id)
    if len(ts) == 0:  # 之前没有，新录入
        wa = WorkspaceAuth()
        wa.ws_id = sso.ws_id
    else:
        wa = ts[0]
    result = wa.auth_info[0]

    exp =result.exp
    if int(time.time()) > exp:
    #if 1==1:
        wa.auth_info = []
        token, session = legalize_ws(account, sso)
        auth = AuthSession(session, account)
        a = decode(token.split(" ", 1)[1], options={"verify_signature": False})
        data = {"Authorization": token, "Cookie": session.cookies}
        auth_info = AuthInfo()
        auth_info.describe = account.username
        auth_info.url_pattern = "/*"
        auth_info.auth_header = data
        auth_info.exp = a["exp"]
        wa.auth_info.append(auth_info)
        wa.save()
        return auth
    else:
        return False

def verify_account(ais: list):
    """
    校验账号是否存在且有效
    :param ais: [account.id, account.id, ...]
    :return:
    """
    assert isinstance(ais, list)
    valid_num = SsoAccount.objects(id__in=ais, status=SsoAccount.STATUS_VALID).count()
    return valid_num == len(ais)


def workspace_sso_conf(_id, data):
    """
    配置工作空间（示例sso认证）
    :param _id:
    :param data:
    :return:
    """
    ts = WorkspaceSso.objects(ws_id=_id)
    if len(ts) == 0:  # 之前没有，新录入
        ws = WorkspaceSso()
        ws.ws_id = _id
    else:
        ws = ts[0]
    if not isinstance(data.get('roles'), dict):
        raise LibException('请至少选择一个账号！')
    ws.roles = data.get('roles')
    ws.redirect_url = data.get('redirect_url')
    ws.portal_site = data.get('portal_site')
    ws.save()




def deal_with_sso(header: HeaderModel, body: BodyModel, name, packet_record: PacketRecord,
                  sso: WorkspaceSso, ws: Workspace):
    """
    处理sso认证的系统
    :param header:
    :param body:
    :param name:
    :param packet_record:
    :param sso:
    :param ws:
    :return:
    """
    rs = redis.Redis(connection_pool=redis_pool)
    hm_key = "{}:{}".format(name, ws.id)  # session
    logger.info("{} deal with sso: {}".format(name, header.url))
    _header = header.header
    if 'Cookie' in _header.keys():
        _header.pop('Cookie')

    for account_id, describe in sso.roles.items():
        account = SsoAccount.objects(id=account_id)
        if len(account) == 0:
            logger.error("no {}->{}!".format(account_id, describe))
            continue
        account = account[0]
        assert isinstance(account, SsoAccount)
        _r = describe if describe else account.describe if account.describe else account.username

        try:
            if account.username == '-':  # 空角色
                if body.type == BodyModel.TYPE_JSON:
                    raw_rest = requests_request(header.method, header.url, json=body.body(), headers=_header)
                elif body.type in [BodyModel.TYPE_FORM, BodyModel.TYPE_BYTE]:
                    raw_rest = requests_request(header.method, header.url, json=body.body(), headers=_header)
                else:
                    raise ParserException("Illegal body type{}".format(body.type))
            else:  # 正常账号
                '''
                auth_session = verify_session(account, sso)
                if  auth_session==False:
                    auth_session = pickle.loads(auth_session)
                else:
                    rs.hset(hm_key, str(account.id), pickle.dumps(auth_session))
                '''
                auth_session = rs.hmget(hm_key, str(account.id))[0]
                if not auth_session:
                    token, session = legalize_ws(account, sso)
                    auth_session = AuthSession(session, account)

                    rs.hset(hm_key, str(account.id), pickle.dumps(auth_session))
                else:
                    auth_session = pickle.loads(auth_session)

                rs.expire(hm_key, 60 * session_timeout)  # 重设超时时间

                if body.type == body.TYPE_JSON:
                    raw_rest = auth_session.request(header.method, header.url, json=body.body(), headers=_header)
                elif body.type in [BodyModel.TYPE_FORM, BodyModel.TYPE_BYTE]:
                    raw_rest = auth_session.request(header.method, header.url, data=body.body(), headers=_header)
                else:
                    raise ParserException('Illegal body type {}'.format(body.type))
        except Exception as e:
            logger.error("{} {} processing error!".format(account_id, describe), exc_info=True)

            if isinstance(e, AccountException):  # 账号失效
                account.status = SsoAccount.STATUS_INVALID
                account.save()
            packet_data = PacketData(banner=gen_banner(_r, header.method, header.url, str(e)), role_describe=_r)
            packet_data.save()
            packet_record.per_packets.append(packet_data)
        else:
            resp_body = BodyModel(raw_rest.content, charset=raw_rest.encoding)
            packet_data = PacketData(banner=gen_banner(_r, header.method, header.url, raw_rest.text),
                                     role_describe=_r,
                                     request=Request(url=header.url, method=header.method,
                                                     header=raw_rest.request.headers,
                                                     body_content=body.content, body_type=body.type),
                                     response=Response(status_code=raw_rest.status_code, header=raw_rest.headers,
                                                       body_content=resp_body.content, body_type=resp_body.type))
            packet_data.save()
            packet_record.per_packets.append(packet_data)

def pwd_encoding(pwd):
    m = hashlib.md5()
    b = pwd.encode(encoding='utf-8')
    m.update(b)
    str_md5 = m.hexdigest()
    return str_md5

def legalize_ws(account: SsoAccount, sso: WorkspaceSso) -> requests.Session:
    """
    使用该账号认证该工作空间
    :param account:
    :param sso:
    :return: session
        def get_refresh_token(self, username, pwd):
        # 获取新版token
        url = base_URL + '/product/verification'
        headers = {
            "Content-Type": "application/json",
            "Authorization": self.get_Authorization(username, pwd)
        }
        body = {
            "browserid": "9800a0cf537bd048764127a8618d172",
            "browsertype": "chrome"
        }
        res = requests.post(url=url, headers=headers, json=body)
        print(res.status_code)
        print(res.content)
        print(res.text)
        try:
            foo: dict = json.loads(res.text)
            refresh_token: str = 'Bearer' + ' ' + foo['access_token']
            with open(refresh_token_file, 'w+', encoding='utf-8') as f:
                f.write(refresh_token)
            print(refresh_token)
            return refresh_token
        except Exception as F:
            print(F)
            self.login(username, pwd)
            with open(token_file, 'r') as f:
                token: str = f.read()
            return token
    """





    logger.info("{} 工作空间认证：".format(account.username))
    # Auth/login hosts are environment-configurable so the same SSO flow can
    # target different environments without code changes. Set:
    #   API_MANAGER_SSO_AUTH_URL   e.g. https://auth.example.com/authorization
    #   API_MANAGER_SSO_LOGIN_URL  e.g. https://login.example.com/login/token-login
    import os as _os
    url = _os.getenv("API_MANAGER_SSO_AUTH_URL", "https://auth.example.com/authorization")
    login_url = _os.getenv("API_MANAGER_SSO_LOGIN_URL", "https://login.example.com/login/token-login")
    session = requests.Session()
    try:

        #rest = session.get(sso.portal_site, proxies=proxies, verify=False, timeout=timeout)
        _init_token = "MjQig6nQ8EgJBEFiImgxievEaBbKNxpZ"
        _init_time = int(time.time())
        data = {
            'account': account.username,
            'ismd5': True,
            "token": pwd_encoding((account.username + pwd_encoding(_init_token) + str(_init_time))),
            "timestamp": _init_time,
            'password': pwd_encoding(account.password)
        }
        logger.debug("sso login token hash prepared for user=%s", account.username)
        res = requests.post(url, proxies=proxies, json=data, verify=False, timeout=timeout)
        logger.debug("sso auth status=%s", res.status_code)
        foo: dict = json.loads(res.text)
        access_token: str = 'Bearer' + ' ' + foo['access_token']
        requests.post(url, json=data, proxies=proxies, verify=False, timeout=timeout)
        url1 = login_url + "?token=" + foo['access_token']
        logger.debug("sso token login redirect prepared for user=%s", account.username)
        session.get(url1, proxies=proxies, verify=False, timeout=timeout)
        header = {"Authorization": access_token}
        session.headers.update(header)
    except Exception as e:
        raise AccountException(e)
    return access_token, session

def _sso_password_verify(username, password):
    """
    可在此处校验密码是否正确
    :param username:
    :param password:
    :return:
    """
    # ...
    return True


def sso_account_record(username, password, describe, _id=None):
    """
    记录 sso 账号信息
    :param username: 用户名
    :param password: 密码
    :param describe: 角色描述
    :param _id: 若有，则更新，否则添加
    :return:
    """
    if not username:
        raise AccountException("未知用户名！")

    if username != '-':  # 默认可存储空账号
        if not _sso_password_verify(username, password):
            raise AccountException("无效的密码！")

    if _id:  # 更新
        sso_accounts = SsoAccount.objects(id=_id)
        if len(sso_accounts) != 1:
            raise AccountException("未找到对应账号信息")
        sso_account = sso_accounts[0]
    else:
        sso_account = SsoAccount()
    sso_account.username = username
    sso_account.password = password
    sso_account.describe = describe
    sso_account.status = SsoAccount.STATUS_VALID
    sso_account.save()


__all__ = [
    "verify_account", "workspace_sso_conf", "deal_with_sso", "legalize_ws", "sso_account_record"
]
