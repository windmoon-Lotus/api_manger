import re
import datetime
from typing import Type

from mongoengine import *
from mongoengine.base import BaseField
from apiAnalysis.conf.conf import logger


# ================================= ↓ example sso ↓ ========================================
class SsoAccount(Document):
    STATUS_VALID = 'valid'
    STATUS_INVALID = 'invalid'

    username = StringField(required=True)
    password = StringField(required=True)
    describe = StringField()
    status = StringField(required=True, default='valid')

    meta = {'collection': 'sso_account'}


class WorkspaceSso(Document):
    """
    自动认证sso所需要的一些信息
    本示例比较简单，实际上只用首页地址即可
    """
    ws_id = ObjectIdField(required=True)
    roles = DictField()
    portal_site = StringField()
    redirect_url = StringField()

    meta = {'collection': 'workspace_sso'}


# ================================= ↓ direct ↓ ========================================
class AuthInfo(EmbeddedDocument):
    """
    认证信息（WorkspaceAuth.auth_info)
    """
    describe = StringField(required=True)
    url_pattern = StringField(required=True)
    auth_header = DictField()
    auth_param = DictField()
    auth_args = DictField()


class WorkspaceAuth(Document):
    ws_id = ObjectIdField(required=True)
    auth_info = ListField(EmbeddedDocumentField(AuthInfo))

    meta = {'collection': 'workspace_auth'}


# ================================= ↓ 工作空间 ↓ ========================================
class Workspace(Document):
    STATUS_INIT = 'init'
    STATUS_START = 'start'
    STATUS_STOP = 'stop'
    STATUS_FINISH = 'finish'

    TYPE_SSO = 'sso'  # 示例sso
    TYPE_DIRECT = 'direct'  # 手动录入信息

    """
    工作空间
    """
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    cname = StringField(required=True)
    status = StringField(required=True, default='init')
    depart_name = StringField()
    system_name = StringField()
    system_type = StringField()
    hosts = ListField(StringField())

    meta = {'collection': 'workspace'}

    @staticmethod
    def ws_status():
        """
        返回工作空间状态
        :return:
        """
        return {i: Workspace.__dict__[i] for i in Workspace.__dict__ if str(i).startswith("STATUS_")}

    @staticmethod
    def sys_types():
        """
        返回系统类型
        :return:
        """
        return {i: Workspace.__dict__[i] for i in Workspace.__dict__ if str(i).startswith("TYPE_")}


# ================================= ↓ 数据包 ↓ ========================================
class Request(EmbeddedDocument):
    """
    请求包
    """
    url = StringField(required=True)
    method = StringField(required=True)
    header = DictField()
    body_content = BaseField()  # 请求体
    body_type = StringField()  # 请求头类型：json/form/xml/bytes (若为bytes类型，则在base64编码后存储)


class Response(EmbeddedDocument):
    """
    响应包
    """
    status_code = IntField(required=True)
    header = DictField()
    body_content = BaseField()
    body_type = StringField()  # 与request相同


class PacketData(Document):
    """
    数据包(PacketRecord.raw_packet / PacketRecord.per_packets)
    """
    banner = StringField(required=True)
    role_describe = StringField(required=True)
    request = EmbeddedDocumentField(Request)
    response = EmbeddedDocumentField(Response)

    meta = {'collection': 'packet_data'}

    @staticmethod
    def raw_query(banner, nor_banner):
        banner = [i.strip() for i in str(banner).split("|") if i.strip() != '']
        nor_banner = [i.strip() for i in str(nor_banner).split("|") if i.strip() != '']
        raw = {
            '$where': """function(){{
                var flag = false;
                if ({}.length == 0){{
                    flag = true;
                }}else{{
                    for(i in {}){{
                        if(this.banner.includes({}[i])){{
                            flag = true;
                            break;
                        }}
                    }}
                }}
                if (flag && {}.length > 0){{
                    for(i in {}){{
                        if(this.banner.includes({}[i])){{
                            flag = false;
                            break;
                        }}
                    }}
                }}
                return flag;
            }}""".format(banner, banner, banner, nor_banner, nor_banner, nor_banner)
        }
        return raw


class PacketRecord(Document):
    """
    流量包
    """
    ws_id = ObjectIdField(required=True)
    username = StringField(required=True)  # 标识用户身份
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    is_delete = BooleanField(default=False)  # 删除标识

    raw_packet = ReferenceField(PacketData)
    per_packets = ListField(ReferenceField(PacketData))

    meta = {'collection': 'packet_record'}

# ================================= ↑ 数据包 ↑ ========================================


class raw_data(Document):
    _id = ObjectIdField(primary_key=True)
    source = StringField()
    source_id = StringField()
    source_meta = DictField()
    asset_kind = StringField(default="concrete")
    abstract_signature = StringField()
    domain = StringField()
    path = StringField(required=True)
    ptah_id = IntField(required=True)
    query = DictField()
    method = StringField(required=True)
    url = StringField(required=True)
    headers = DictField()
    action = StringField()
    class_confidence = IntField(default=0)
    class_reason_codes = ListField(StringField())
    rule = StringField(default="path")
    des = StringField()
    Max_records = IntField()
    tags = StringField()
    raw_req = ListField()
    raw_res = ListField()
    response_status_code = ListField()
    modificator = StringField()
    meta = {
        'collection': 'rawData',
        'indexes': [
            'source',
            'source_id',
            'asset_kind',
            'abstract_signature',
            'domain',
            'ptah_id',
        ]
    }


class req_data(Document):
    raw_data = ReferenceField(raw_data, required=True)
    source_meta = DictField()
    Content_type = StringField()
    parameter = StringField()
    position = StringField()
    relation = StringField()
    Priority = IntField()
    value = ListField()
    required = BooleanField()
    type = StringField()
    des = StringField()
    modificator = StringField()
    meta = {
        'collection': 'reqParseData'
    }


class res_data(Document):
    raw_data = ReferenceField(raw_data, required=True)
    source_meta = DictField()
    Content_type = StringField()
    parameter = StringField()
    value = ListField()
    type = StringField()
    des = StringField()
    position = StringField()
    relation = StringField()
    modificator = StringField()
    meta = {
        'collection': 'resParseData'
    }


class parameter_data(Document):
    parameter = StringField(required=True)
    parameterid = IntField(required=True)
    req_pathid = ListField()
    res_pathid = ListField()
    req_value = ListField()
    res_value = ListField()
    modificator = StringField()
    meta = {
        'collection': 'parameterData',
        'indexes': [
            'parameter',
            'parameterid',
        ]
    }

    @staticmethod
    def get_editable_fields():
        return ['parameter', 'req_value', 'res_value']

class parameter_archive(Document):
    parameter = StringField(required=True)
    parameterid = ListField(required=True)
    #parameter_value = IntField()
    req_pathid = ListField()
    res_pathid = ListField()
    req_value = ListField()
    res_value = ListField()
    properties = ListField()
    modificator = StringField()
    account_id = StringField()
    meta = {
        'collection': 'parameterArchive'
    }

class parameter_relation(Document):
    parameter = StringField(required=True)
    req_pathid = IntField(required=True)
    res_pathid = IntField(required=True)
    rule = StringField()
    relation = StringField()
    score = FloatField()
    reason_codes = ListField(StringField())
    evidence = ListField()
    verified = BooleanField(default=False)
    modificator = StringField()
    meta = {
        'collection': 'parameterRelation'
    }


class idor_parameter_candidate(Document):
    """
    Endpoint-scoped parameter role used by IDOR construction.

    parameter_archive stores raw observed values. This collection stores the
    security meaning of a parameter for one endpoint so later tests know which
    values can be replayed, swapped, or must be kept as auth/context.
    """
    pathid = IntField(required=True)
    raw_data = ReferenceField(raw_data)
    method = StringField()
    path = StringField()
    parameter = StringField(required=True)
    position = StringField()
    param_type = StringField()
    required = BooleanField(default=False)
    role = StringField(default="unknown")
    role_confidence = FloatField(default=0.0)
    reason_codes = ListField(StringField())
    source_meta = DictField()
    sample_values_by_account = DictField()
    relation_refs = ListField(DictField())
    manual_role = StringField()
    manual_note = StringField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    mtime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'idorParameterCandidate',
        'indexes': [
            'pathid',
            'parameter',
            'role',
            'manual_role',
        ]
    }


class idor_construction_trace(Document):
    """
    Reproducible construction record for one generated IDOR/security test case.
    """
    run_id = ObjectIdField()
    result_id = ObjectIdField()
    pathid = IntField(required=True)
    case_name = StringField()
    check_type = StringField()
    method = StringField()
    path = StringField()
    owner_account = StringField()
    attacker_account = StringField()
    selected_parameters = DictField()
    kept_parameters = DictField()
    mutations = ListField(DictField())
    value_sources = DictField()
    request_before = DictField()
    request_after = DictField()
    strategy = StringField()
    strategy_reason = StringField()
    judge_inputs = DictField()
    verdict = StringField()
    reason_codes = ListField(StringField())
    evidence_ref = StringField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'idorConstructionTrace',
        'indexes': [
            'run_id',
            'result_id',
            'pathid',
            'check_type',
            'verdict',
            '-ctime',
        ]
    }


class Counter(Document):
    _id = StringField(primary_key=True)
    sequence_value = IntField(default=11111)

    @queryset_manager
    def objects(doc_cls, queryset):
        # 这个自定义的objects管理器可以添加额外的方法
        return queryset


class generate_req(Document):
    pathid = IntField(required=True)
    parameterids = ListField()
    parameters = ListField()
    Content_type = StringField()
    modificator = StringField()
    meta = {
        'collection': 'baseGenerateReq'
    }


class request_snapshot(Document):
    """
    A reproducible request built from one API asset.

    Snapshot records are the handoff contract between interface assets and
    executors such as replay, sqlmap, nuclei, Schemathesis, or custom IDOR
    checks. Keep this model boring and explicit: it should describe one HTTP
    request without requiring callers to understand raw_data/req_data internals.
    """
    pathid = IntField(required=True)
    raw_data = ReferenceField(raw_data)
    source = StringField(default="asset")
    env_id = StringField()
    account_id = StringField()
    method = StringField(required=True)
    url = StringField(required=True)
    path = StringField()
    domain = StringField()
    query = DictField()
    headers = DictField()
    cookies = DictField()
    path_params = DictField()
    body = BaseField()
    content_type = StringField(default="application/json")
    expected_status_codes = ListField()
    parameter_sources = DictField()
    metadata = DictField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'requestSnapshot',
        'indexes': [
            'pathid',
            'source',
            'env_id',
            'account_id',
            '-ctime',
        ]
    }


class request_sample(Document):
    """
    A bounded representative request captured from HAR/flow traffic.

    raw_data/req_data describe the API template and parameter knowledge.
    request_sample preserves a few real executable contexts per API so replay
    does not lose the binding between URL, query, headers, body, and response.
    """
    pathid = IntField(required=True)
    raw_data = ReferenceField(raw_data, required=True)
    sample_signature = StringField(required=True)
    source = StringField(default="traffic")
    method = StringField(required=True)
    url = StringField(required=True)
    path = StringField()
    domain = StringField()
    query = DictField()
    headers = DictField()
    body = BaseField()
    body_shape = DictField()
    response_status_code = IntField()
    response_len = IntField(default=0)
    response_hash = StringField()
    response_sample = BaseField()
    hit_count = IntField(default=1)
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    last_seen = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'requestSample',
        'indexes': [
            'pathid',
            'sample_signature',
            '-last_seen',
            {'fields': ['raw_data', 'sample_signature'], 'unique': True},
        ]
    }


class target_whitelist(Document):
    pathid = IntField(required=True)
    scenario = StringField(required=True)
    reason = StringField()
    meta = {
        'collection': 'targetWhitelist'
    }


class privilege_task(Document):
    STATUS_INIT = 'init'
    STATUS_SKIP = 'skip'
    STATUS_DONE = 'done'

    pathid = IntField(required=True)
    scenario = StringField(required=True)
    status = StringField(required=True, default=STATUS_INIT)
    result = StringField()
    evidence = DictField()
    rule_score = FloatField()
    rule_reason_codes = ListField(StringField())
    ai_prompt = StringField()
    ai_result = StringField()
    ai_reason = StringField()
    ai_score = FloatField()
    ai_confidence = FloatField()
    ai_reason_codes = ListField(StringField())
    final_score = FloatField()
    final_result = StringField()
    prompt_ver = StringField()
    model_ver = StringField()
    ai_raw_ref = StringField()
    judge_version = StringField(default="v1")
    meta = {
        'collection': 'privilegeTask'
    }


class security_test_run(Document):
    """
    One bounded security test execution batch.

    Store only sanitized metadata here. Credentials, raw response bodies, real
    resource ids, and full private evidence should remain in local private files
    referenced by evidence_ref.
    """
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"

    name = StringField(required=True)
    profile_id = StringField()
    check_type = StringField(required=True)
    scope = DictField()
    source = StringField(default="manual")
    status = StringField(required=True, default=RUNNING)
    summary = DictField()
    evidence_ref = StringField()
    started_at = DateTimeField(default=datetime.datetime.utcnow)
    finished_at = DateTimeField()
    operator = StringField()
    notes = StringField()

    meta = {
        'collection': 'securityTestRun',
        'indexes': [
            'profile_id',
            'check_type',
            'status',
            '-started_at',
        ]
    }


class security_test_result(Document):
    """
    Sanitized conclusion for one security test case within a run.
    """
    run_id = ObjectIdField(required=True)
    case_name = StringField(required=True)
    check_type = StringField(required=True)
    target = DictField()
    method = StringField()
    verdict = StringField(required=True)
    priority = StringField()
    severity = StringField()
    confidence = FloatField()
    reason_codes = ListField(StringField())
    evidence_summary = DictField()
    evidence_ref = StringField()
    related_pathid = IntField()
    related_vuln_id = ObjectIdField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'securityTestResult',
        'indexes': [
            'run_id',
            'check_type',
            'verdict',
            'priority',
            'related_pathid',
            '-ctime',
        ]
    }


class privilege_config(Document):
    ws_id = ObjectIdField(required=True)
    scenario = StringField(required=True)
    account_id = StringField()
    baseline_account_id = StringField()
    auth_describe = StringField()
    baseline_auth_describe = StringField()
    enabled = BooleanField(default=True)
    meta = {
        'collection': 'privilegeConfig'
    }


class api_version(Document):
    name = StringField(required=True)
    version = StringField(required=True)
    base_url = StringField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    meta = {
        'collection': 'apiVersion'
    }


class vuln_record(Document):
    pathid = IntField()
    scenario = StringField()
    severity = StringField()
    status = StringField(default="open")
    result = StringField()
    evidence = DictField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    meta = {
        'collection': 'vulnRecord'
    }


class test_case(Document):
    name = StringField(required=True)
    pathid = IntField()
    method = StringField()
    url = StringField()
    headers = DictField()
    body = BaseField()
    expected = DictField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    meta = {
        'collection': 'testCase'
    }


def modify_data(collection: Type[Document], action: str, query: dict = None, data: dict = None) -> bool:
    """
    修改数据库中的数据。

    :param collection: MongoEngine的Document类，表示要操作的集合。
    :param action: 要执行的操作类型，如"insert"、"update"、"delete"。
    :param query: 查询条件字典。
    :param data: 要插入或更新的数据字典。
    :return: 操作成功返回True，否则返回False。
    """
    try:
        if action == "insert":
            if data:
                collection(**data).save()
            else:
                return False  # 插入操作需要数据
        elif action == "update":
            if query and data:
                collection.objects(**query).update(**data)
            else:
                return False  # 更新操作需要查询条件和数据
        elif action == "delete":
            if query:
                collection.objects(**query).delete()
            else:
                return False  # 删除操作需要查询条件
        elif action == "query":
            if query:
                return collection.objects(**query)
            else:
                return False
        else:
            return False  # 不支持的操作
        return True
    except Exception as e:
        logger.exception("modify_data failed: %s", e)
        return False


#modify_data(generate_req, "insert", data={"name": "John Doe", "age": 30})

# 更新数据示例
##modify_data(generate_req, "delete", query={"name": "John Doe"})
#data = modify_data(raw_data, "query", query={"ptah_id": 8980})


if __name__ == '__main__':
    account = SsoAccount()
    account.username = '-'
    account.describe = '空'
    account.save()
