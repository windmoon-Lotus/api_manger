import json
import random
import urllib
from typing import Any
from urllib.parse import parse_qs, urlparse

from apiAnalysis.conf.conf import replacements, logger
from apiAnalysis.tool.parameter_locator import materialize_flat_json


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
        if not value:
            return []
        return random.choice(value)
    return value


def _coerce_selected_value(value, value_selector):
    selected_value = value_selector(value)
    if isinstance(selected_value, str):
        try:
            return json.loads(selected_value)
        except json.JSONDecodeError:
            return selected_value
    return selected_value


def unflatten_json(flat_json, value_selector=random_select):
    """Restore concrete and schema-style paths such as ``items[].id``.

    New request composition uses typed locators and therefore does not need to
    guess container types.  This legacy helper remains for callers that only
    have dotted names; schema ``[]`` paths materialize one representative item
    and a numeric root is treated as an object key to avoid huge accidental
    list allocations.
    """
    return materialize_flat_json(
        flat_json,
        value_selector=lambda value: _coerce_selected_value(value, value_selector),
    )


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
