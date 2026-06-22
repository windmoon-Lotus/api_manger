payloads = []


def add_payload(data, payload="' OR 1=1 -- ", target='value'):
    """
    递归遍历数据结构，并拼接Payload，同时处理符号闭合关系。

    :param data: 输入的数据结构（字典、列表等）。
    :param payload: 要拼接的Payload。
    :param target: 拼接目标，'key'（键）、'value'（值）或'both'（键和值）。
    :return: 拼接后的数据结构。
    """
    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            new_key = key
            new_value = value
            if target in ['key', 'both']:
                new_key = f"{key}{payload}"  # 在键上拼接Payload
            if target in ['value', 'both']:
                if isinstance(value, (dict, list)):
                    new_value = add_payload(value, payload, target)  # 递归处理嵌套结构
                else:
                    new_value = apply_payload(value, payload)  # 处理符号闭合关系
            result[new_key] = new_value
        return result
    elif isinstance(data, list):
        result = []
        for item in data:
            if isinstance(item, (dict, list)):
                result.append(add_payload(item, payload, target))  # 递归处理嵌套结构
            else:
                if target in ['value', 'both']:
                    result.append(apply_payload(item, payload))  # 处理符号闭合关系
                else:
                    result.append(item)
        return result
    else:
        if target in ['value', 'both']:
            return apply_payload(data, payload)
        else:
            return data


def apply_payload(value, payload):
    """
    在值上拼接Payload，并处理符号闭合关系。

    :param value: 原始值。
    :param payload: 要拼接的Payload。
    :return: 拼接后的值。
    """
    if isinstance(value, str):
        # 检查字符串是否以引号开头和结尾
        if value.startswith("'") and value.endswith("'"):
            return f"{value[:-1]}{payload}'"  # 闭合单引号
        elif value.startswith('"') and value.endswith('"'):
            return f'{value[:-1]}{payload}"'  # 闭合双引号
        else:
            return f"{value}{payload}"  # 无引号，直接拼接
    elif isinstance(value, (int, float, bool)):
        return f"{value}{payload}"  # 数字或布尔值，直接拼接
    else:
        return value  # 其他类型（如None），不处理


def add_payload_generator(data, payload="' OR 1=1 -- ", target='value', stop_flag=None):
    """
    递归遍历数据结构，逐个替换拼接好的数据并通过 yield 返回。

    :param data: 输入的数据结构（字典、列表等）。
    :param payload: 要拼接的Payload。
    :param target: 拼接目标，'key'（键）、'value'（值）或'both'（键和值）。
    :param stop_flag: 外部标志，用于中止循环。
    :yield: 每次替换后的数据结构。
    """
    if isinstance(data, dict):
        for key, value in data.items():
            if stop_flag and stop_flag.is_set():  # 检查外部标志
                return
            new_data = data.copy()
            if target in ['key', 'both']:
                new_key = apply_payload(key, payload)  # 在键上拼接Payload
                new_data.pop(key)  # 移除旧键
                new_data[new_key] = value  # 添加新键
            if target in ['value', 'both']:
                if isinstance(value, (dict, list)):
                    # 递归处理嵌套结构
                    for modified_nested in add_payload_generator(value, payload, target, stop_flag):
                        new_data[key] = modified_nested
                        yield new_data
                else:
                    new_data[key] = apply_payload(value, payload)  # 在值上拼接Payload
                    yield new_data
    elif isinstance(data, list):
        for index, item in enumerate(data):
            if stop_flag and stop_flag.is_set():  # 检查外部标志
                return
            new_data = data.copy()
            if isinstance(item, (dict, list)):
                # 递归处理嵌套结构
                for modified_nested in add_payload_generator(item, payload, target, stop_flag):
                    new_data[index] = modified_nested
                    yield new_data
            else:
                if target in ['value', 'both']:
                    new_data[index] = apply_payload(item, payload)  # 在值上拼接Payload
                    yield new_data
    else:
        if target in ['value', 'both']:
            yield apply_payload(data, payload)
        else:
            yield data


data = {
    "id": "1",
    "name": "test",
    "tags": ["python", "security"],
    "details": {
        "age": "25",
        "hobbies": ["reading", "coding"]
    }
}

for modified_data in add_payload_generator(data, payload="' OR 1=1 -- "):
    print(modified_data)
