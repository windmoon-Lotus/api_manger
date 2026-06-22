import json
import pickle
import random
import re
import urllib
from typing import Any
from urllib.parse import parse_qs, urlparse

import redis

from apiAnalysis.conf.conf import replacements, logger, session_timeout
from apiAnalysis.core.identify.sso import legalize_ws
from apiAnalysis.db.collection import *
from apiAnalysis.model.exception import ParserException
from apiAnalysis.model.model import HeaderModel, BodyModel, AuthSession
from apiAnalysis.db.collection import SsoAccount
from apiAnalysis.tool import redis_pool


def load_data_from_mongodb(collection_name):
    collection = collection_name  # 获取集合
    data = list(collection.find({}))  # 查询数据并排除 _id 字段
    return data
def extract_url_params(url):
    # 解析URL
    parsed_url = urlparse(url)
    path = parsed_url.path
    # 使用parse_qs方法从查询字符串中提取参数
    query_params = parse_qs(parsed_url.query)
    # parse_qs包装了值在列表中，这将提取每个参数的第一个值
    params = {k: v[0] if len(v) == 1 else v for k, v in query_params.items()}
    return path, params


def regex_path(path):
    for pattern, repl in replacements:
        path = pattern.sub(repl, path)
    return path


def flatten_json(data, parent_key='', separator='.'):
    """
    将嵌套的 JSON 数据平坦化。

    :param data: 要处理的数据（字典或列表或其他）
    :param parent_key: 父级键名（用于递归）
    :param separator: 键之间的分隔符，默认为点号
    :return: 平坦化后的字典
    """
    items = {}

    # 如果顶层是列表
    if isinstance(data, list):
        for idx, item in enumerate(data):
            list_key = f"{parent_key}{separator}{idx}" if parent_key else str(idx)
            if isinstance(item, (dict, list)):
                # 递归处理嵌套列表或字典
                items.update(flatten_json(item, list_key, separator))
            else:
                items[list_key] = item

    # 如果顶层是字典
    elif isinstance(data, dict):
        for key, value in data.items():
            new_key = f"{parent_key}{separator}{key}" if parent_key else key
            if isinstance(value, (dict, list)):
                # 递归处理嵌套字典或列表
                items.update(flatten_json(value, new_key, separator))
            else:
                items[new_key] = value

    # 如果是基本数据类型
    else:
        items[parent_key] = data

    return items


def random_select(value):
    """
    从 value 中随机选择一个值。
    如果 value 是数组，则随机选择一个元素；否则直接返回 value。
    """
    if isinstance(value, list):
        return random.choice(value)
    return value


def unflatten_json(flat_json, value_selector=random_select):
    """
    将扁平化的 JSON 恢复为嵌套 JSON。
    :param flat_json: 扁平化的 JSON 数据（字典格式）。
    :param value_selector: 用于选择 value 的函数，默认为随机选择。
    :return: 恢复后的嵌套 JSON。
    """
    result = {}
    for key, value in flat_json.items():
        parts = key.split('.')
        current_level = result
        for part in parts[:-1]:
            if part not in current_level:
                current_level[part] = {}
            current_level = current_level[part]

        # 使用 value_selector 选择 value
        selected_value = value_selector(value)

        # 如果 selected_value 是 JSON 字符串，则解析为 JSON 对象
        if isinstance(selected_value, str):
            try:
                selected_value = json.loads(selected_value)
            except json.JSONDecodeError:
                pass

        current_level[parts[-1]] = selected_value
    return result


def _is_list_index(part):
    return isinstance(part, str) and part.isdigit()


def _new_container(next_part):
    return [] if _is_list_index(next_part) else {}


def _ensure_list_size(items, index):
    while len(items) <= index:
        items.append(None)


def _coerce_selected_value(value, value_selector):
    selected_value = value_selector(value)
    if isinstance(selected_value, str):
        try:
            return json.loads(selected_value)
        except json.JSONDecodeError:
            return selected_value
    return selected_value


def unflatten_json(flat_json, value_selector=random_select):
    """Restore flattened JSON while preserving list indexes such as items.0.id."""
    if not flat_json:
        return {}
    first_key = next(iter(flat_json.keys()))
    result = [] if _is_list_index(str(first_key).split(".")[0]) else {}
    for key, value in flat_json.items():
        parts = str(key).split(".")
        current_level = result
        for idx, part in enumerate(parts):
            is_last = idx == len(parts) - 1
            next_part = None if is_last else parts[idx + 1]
            selected_value = _coerce_selected_value(value, value_selector) if is_last else None

            if isinstance(current_level, list):
                if not _is_list_index(part):
                    raise ValueError("list path segment must be numeric: {}".format(part))
                list_index = int(part)
                _ensure_list_size(current_level, list_index)
                if is_last:
                    current_level[list_index] = selected_value
                else:
                    if current_level[list_index] is None or not isinstance(current_level[list_index], (dict, list)):
                        current_level[list_index] = _new_container(next_part)
                    current_level = current_level[list_index]
                continue

            if is_last:
                current_level[part] = selected_value
            else:
                if part not in current_level or not isinstance(current_level[part], (dict, list)):
                    current_level[part] = _new_container(next_part)
                current_level = current_level[part]
    return result


def body_parse(body):
    if body is not None:
        body_val = None
        content_type = None
        # try to parse the body as json
        try:
            body_val = json.loads(body)
            content_type = "application/json"
            #print(body, "json")
            return body_val, content_type
        except UnicodeDecodeError:
            pass
        except json.decoder.JSONDecodeError:
            pass
        if content_type is None:
            # try to parse the body as form data
            try:
                body_val_bytes: Any = dict(
                    urllib.parse.parse_qsl(
                        body, encoding="utf-8", keep_blank_values=True
                    )
                )
                body_val = {}
                did_find_anything = False
                for key, value in body_val_bytes.items():
                    did_find_anything = True
                    decoded_key = key.decode("utf-8") if isinstance(key, bytes) else key
                    decoded_value = value.decode("utf-8") if isinstance(value, bytes) else value
                    body_val[decoded_key] = decoded_value
                if did_find_anything:
                    content_type = "application/x-www-form-urlencoded"
                    #print(body, "x-www-form")
                    return body_val, content_type
                else:
                    #print(body, "None")
                    return body_val, content_type
            except UnicodeDecodeError:
                logger.debug("UnicodeDecodeError encountered while parsing form data")
            except Exception as e:
                logger.debug("An unexpected error occurred while parsing form data: %s", e)



def get_request(req_pathid):
    rawdata = raw_data.objects(ptah_id=req_pathid).first()
    if urllib.parse.urlencode(rawdata.query) is not None:
        url = rawdata.domain + rawdata.path + "?" + urllib.parse.urlencode(rawdata.query)
    else:
        url = rawdata.domain + rawdata.path
    HeaderModel(url=url, method=rawdata.method, header=rawdata.headers)
    if len(rawdata.raw_req) > 0:
        BodyModel(rawdata.raw_req[0])
    else:
        BodyModel(None)

    return HeaderModel, BodyModel


def deal_raw(parameterdict):
    for key, value in parameterdict.items():
        #print(f"{key}: {value}")
        for v in value:
            parameter = parameter_data.objects(parameterid=v).first()
            if len(value) <= 1 and len(parameter.req_pathid) <= 1:
                logger.debug("deal_raw single parameter: key=%s, pid=%s", key, v)
                yield key, v, None
                continue
            else:
                for i in parameter.req_pathid:
                    header, body = get_request(i)
                    reqs = {"req_pathid": i, "parameter": key, "parameterid": v}
                    yield header, body, reqs


def deal_request(header: HeaderModel, body: BodyModel, name, ws, sso):
    if header.method not in [HeaderModel.METHOD_GET, HeaderModel.METHOD_POST, HeaderModel.METHOD_DELETE,
                             HeaderModel.METHOD_PUT]:
        logger.error("暂不支持的方法：{}".format(header.method))
        return None
    _header = header.header
    if 'Cookie' in _header.keys():
        _header.pop('Cookie')
    rs = redis.Redis(connection_pool=redis_pool)
    hm_key = "{}:{}".format(name, ws.id)
    flag = False
    for account_id, describe in sso.roles.items():
        account = SsoAccount.objects(id=account_id)
        if account.username == "":
            flag = True
            break
    if not flag:
        logger.info("not right account")
    auth_session = rs.hmget(hm_key, str(account.id))[0]
    if not auth_session:
        token, session = legalize_ws(account)
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
    return raw_rest

def sheer_parameters():
    parameters = parameter_data.objects()
    sheer_parameters = {}
    paths = {}
    for parameter in parameters:
        # print(parameter.req_pathid,parameter.parameter)
        if not parameter.req_pathid:
            continue
        data_parameter = parameter.parameter
        req_pathid = parameter.req_pathid
        res_pathid = parameter.res_pathid
        req_value = parameter.req_value
        res_value = parameter.res_value
        sheer_parameter = data_parameter.split(".")[-1]
        if re.match(r'^\d+$', sheer_parameter) and len(data_parameter.split(".")) > 1:
            sheer_parameter = ".".join(data_parameter.split(".")[-2:])
        if sheer_parameter not in sheer_parameters:
            sheer_parameters[sheer_parameter] = [parameter.parameterid]
            paths[sheer_parameter] = {"req_pathid": req_pathid, "res_pathid": res_pathid,
                                      "req_value": req_value, "res_value": res_value}
        # print(sheer_parameters)
        else:
            sheer_parameters[sheer_parameter].append(parameter.parameterid)
            paths[sheer_parameter]["req_pathid"].append(req_pathid)
            paths[sheer_parameter]["res_pathid"].append(req_pathid)
            paths[sheer_parameter]["req_value"].append(req_value)
            paths[sheer_parameter]["res_value"].append(res_value)
    return sheer_parameters, paths
