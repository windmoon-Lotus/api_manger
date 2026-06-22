import json
import sys
import pandas as pd

import json5


def parse_ref(path,apipath,summary):
    for data in openapi["components"]["schemas"]:
        if data==path:
            paramets = openapi["components"]["schemas"][data]
            refresult = []
            if paramets.get("type") == "object":
                properties = paramets.get("properties", {})
                for prop_name, prop_info in properties.items():
                    prop_type = parse_request_body(prop_info,apipath,summary,"fasle")
                    #print(prop_name,":",prop_type)
                    if len(prop_type.split(":")[-1])==12:
                        vari = "\"{{" + prop_name + "value" + "}}\""
                    else:
                        vari = "\"{{" + prop_name + prop_type + "}}\""
                    #print(vari)
                    refresult.append(f"{path}:{summary}:{prop_name}:{vari}")
                return "\n  ".join(refresult)



def parse_request_body(schema,path,summary,isexample):
    if isexample == "ture":
        result = []
        if isinstance(schema, dict):
            for prop_name, prop_schema in schema.items():
                key = '"' + prop_name + '"'
                value=""
                if isinstance(prop_schema, dict) and len(prop_schema) > 0:
                    vari = parse_request_body(prop_schema,path,summary,isexample)
                else:
                    vari = "\"{{" + prop_name +"data_packageapi"+ "}}\""
                    value=prop_schema
                didcc=path+":"+key+":"+str(value)+":"+vari+"\n"
                result.append(didcc)
        else:
            print(type(schema))
            for i in range(len(schema)):
                parse_request_body(schema[i], path, summary, isexample)
                return 0
        return "\n  ".join(result)
    if "$ref" in schema:
        ref = schema["$ref"].split("/")[-1]
        data=parse_ref(ref,path,summary)
        #print(data)
        return f"{data}"
    if schema.get("type") == "array":
        items = schema.get("items", {})
        if "$ref" in items:
            ref = items["$ref"].split("/")[-1]
            data=parse_ref(ref,path,summary)
            return f"{data}"
        else:
            return f"array{items.get('type', '')}"
    if schema.get("type") == "object":
        properties = schema.get("properties", {})
        result = []
        for prop_name, prop_schema in properties.items():
            #print("test",prop_name)

            if parse_request_body(prop_schema,path,summary,isexample) == "boolean":
                vari="{{booleantype}}"
            elif "{" in parse_request_body(prop_schema,path,summary,isexample):
                vari=parse_request_body(prop_schema,path,summary,isexample)
            else:
                vari =prop_name+parse_request_body(prop_schema,path,summary,isexample)
            dictpath=path+":"+summary+":"+"{{"+vari+"}}"+"\n"
            #result.append(data)
            result.append(f"{dictpath}")
        #return "\n  ".join(result)
        return  "\n  ".join(result)
    return schema.get("type", "")
def convert_to_string(data):
    if isinstance(data, dict):
        return {convert_to_string(key): convert_to_string(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [convert_to_string(element) for element in data]
    elif isinstance(data, tuple):
        return tuple(convert_to_string(element) for element in data)
    elif isinstance(data, set):
        return {convert_to_string(element) for element in data}
    elif isinstance(data, str):
        return data
    else:
        return str(data)

if __name__ == '__main__':
    #openapi_src = sys.argv[1]
    openapi_src = "../api.openapi.json"
    with open(openapi_src, "r",encoding="utf-8") as f:
        openapi = json.load(f)
    for path, operations in openapi["paths"].items():
        #if path=="/api2/OpenTicketApi.reviewTicketPass":
        for method, operation in operations.items():
            summary = operation.get("summary", "")
            parameters = operation.get("parameters", [])
            requestBody = operation.get("requestBody", {})
            responses = operation["responses"]
            #print(f"{method.upper()} {path}")
            #print(f"摘要: {summary}")
            if parameters:
                #print("参数:")
                parame=[]
                for parameter in parameters:
                    name = parameter["name"]
                    in_ = parameter["in"]
                    required = parameter.get("required", False)
                    schema = parameter.get("schema", {})
                    a=f"  {in_}: {name} ({'必需' if required else '可选'}，{schema.get('type', '')})"
                    parame.append(a)
                #print(parame)
            if requestBody:
                # print("请求体参数:")
                for contentType, content in requestBody.get("content", {}).items():
                    if "example" in content and len(content.get("example", {})) > 0:
                        print(path )
                        body = parse_request_body(json5.loads(content.get("example", {})), path,summary,"ture")
                    else:
                        schema = content.get("schema", {})
                        if "properties" in schema:
                            request_parameters = schema["properties"]
                            #print("request_parameters: ", request_parameters)
                            if len(str(request_parameters))>2:
                                df = pd.json_normalize(request_parameters)
                                print(path, schema)
                                flattened_parameters = df.to_dict('records')[0]
                                print(flattened_parameters)
                            #body = parse_request_body(schema, path,summary,"False")
            else:
                body = ""
            '''
            with open(openapi_src.split(".")[0]+"_parameters.txt", "a",encoding="utf-8") as f:
                f.write(str(body))
                f.close()
                    #print(f"  {contentType}: {body}")
            #print("响应:")
            for status_code, response in responses.items():
                description = response.get("description", "")
                #print(f"  {status_code}: {description}")
            '''

