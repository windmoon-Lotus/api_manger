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


class ApiProject(Document):
    """Stable internal project boundary independent of any import source."""
    ACTIVE = "active"
    ARCHIVED = "archived"

    project_id = StringField(required=True, unique=True)
    name = StringField(required=True)
    status = StringField(default=ACTIVE)
    description = StringField()
    metadata = DictField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    mtime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {'collection': 'apiProject', 'indexes': ['project_id', 'status', 'name']}


class DataSource(Document):
    """Stable, non-secret identity for one document or traffic source.

    A data source describes where observations and document versions come
    from.  It does not own a project, authentication credentials, or imported
    assets.  Project ownership is expressed only through
    ``ProjectSourceBinding``.
    """
    ACTIVE = "active"
    ARCHIVED = "archived"

    data_source_id = StringField(required=True, unique=True)
    source_type = StringField(required=True)
    external_id = StringField(required=True)
    name = StringField(required=True)
    workspace_id = StringField()
    lifecycle = StringField(default=ACTIVE)
    config = DictField()
    current_import_run_id = StringField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    mtime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'dataSource',
        'indexes': [
            'data_source_id', 'source_type', 'external_id', 'workspace_id',
            'lifecycle', '-mtime',
            {
                'fields': ['source_type', 'external_id'],
                'unique': True,
            },
        ],
    }


class ProjectSourceBinding(Document):
    """Bind a project to Apifox/OpenAPI/HAR/Workspace source identities."""
    project_id = StringField(required=True)
    data_source_id = StringField()
    source_type = StringField(required=True)
    source_id = StringField(required=True)
    env_id = StringField()
    workspace_id = StringField()
    routing_rules = DictField()
    active = BooleanField(default=True)
    disabled_by = StringField()
    disabled_at = DateTimeField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    mtime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'projectSourceBinding',
        'indexes': [
            'project_id', 'data_source_id', 'source_type', 'source_id',
            'workspace_id',
            {
                'fields': ['project_id', 'data_source_id', 'env_id'],
                'unique': True,
                'sparse': True,
            },
        ],
    }


class ProjectEnvironment(Document):
    """Executable Host configuration for one project environment."""
    project_id = StringField(required=True)
    env_id = StringField(required=True)
    name = StringField()
    # Mutation is opt-in and only valid for an explicitly classified test or
    # pre-production environment.  Test/pre-production budgets are configured
    # by the owner; production and unknown environments keep a hard safety cap.
    environment_type = StringField(default="unknown")
    allow_mutation = BooleanField(default=False)
    auto_request_limit = IntField(default=3)
    default_host = StringField()
    hosts = ListField(DictField())
    active = BooleanField(default=True)
    metadata = DictField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    mtime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'projectEnvironment',
        'indexes': [
            'project_id', 'env_id', 'active',
            {'fields': ['project_id', 'env_id'], 'unique': True},
        ],
    }


class TestAccount(Document):
    """Stable test-account identity; credentials are versioned separately."""
    ACTIVE = "active"
    RETIRED = "retired"

    account_id = StringField(required=True, unique=True)
    username = StringField(required=True)
    display_name = StringField()
    lifecycle = StringField(default=ACTIVE)
    current_credential_version_id = StringField()
    source_ref = StringField()
    metadata = DictField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    mtime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'testAccount',
        'indexes': ['account_id', 'username', 'lifecycle', 'source_ref'],
    }


class CredentialVersion(Document):
    """Immutable credential material for an internal test account.

    The personal deployment currently permits plaintext test credentials in
    Mongo.  Callers must still avoid logging or copying this mapping into
    snapshots, runs, verification attempts, or source code.
    """
    credential_version_id = StringField(required=True, unique=True)
    account_id = StringField(required=True)
    revision_no = IntField(required=True)
    credential_type = StringField(default="username_password")
    secret_data = DictField(required=True)
    source_ref = StringField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'credentialVersion',
        'indexes': [
            'credential_version_id', 'account_id', '-ctime',
            {'fields': ['account_id', 'revision_no'], 'unique': True},
        ],
    }


class AuthAdapter(Document):
    """Stable identity for a recipe, code, or interactive auth adapter."""
    adapter_id = StringField(required=True, unique=True)
    name = StringField(required=True)
    adapter_type = StringField(default="recipe")
    lifecycle = StringField(default="active")
    description = StringField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    mtime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'authAdapter',
        'indexes': ['adapter_id', 'adapter_type', 'lifecycle'],
    }


class AuthAdapterVersion(Document):
    """Content-addressed immutable declarative authentication recipe."""
    adapter_version_id = StringField(required=True, unique=True)
    adapter_id = StringField(required=True)
    semver = StringField(required=True)
    schema_version = IntField(default=1)
    recipe = DictField(required=True)
    capabilities = ListField(StringField())
    allowed_auth_origins = ListField(StringField())
    artifact_sha256 = StringField(required=True)
    lifecycle = StringField(default="draft")
    ctime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'authAdapterVersion',
        'indexes': [
            'adapter_version_id', 'adapter_id', 'lifecycle',
            {'fields': ['adapter_id', 'semver'], 'unique': True},
            {'fields': ['adapter_id', 'artifact_sha256'], 'unique': True},
        ],
    }


class AuthRealm(Document):
    """Stable identity for one authentication boundary."""
    realm_id = StringField(required=True, unique=True)
    name = StringField(required=True)
    lifecycle = StringField(default="draft")
    current_revision_id = StringField()
    source_ref = StringField()
    description = StringField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    mtime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'authRealm',
        'indexes': ['realm_id', 'lifecycle', 'source_ref'],
    }


class AuthRealmSecretVersion(Document):
    """Immutable Realm-scoped protocol secrets.

    These values are shared by every test account using the same authentication
    Realm, so they must not be copied into account credentials or Recipe JSON.
    The personal deployment permits plaintext test secrets in Mongo, but callers
    must never render, log, or persist them in verification evidence.
    """
    secret_version_id = StringField(required=True, unique=True)
    realm_id = StringField(required=True)
    revision_no = IntField(required=True)
    secret_data = DictField(required=True)
    lifecycle = StringField(default="draft")
    ctime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'authRealmSecretVersion',
        'indexes': [
            'secret_version_id', 'realm_id', 'lifecycle', '-ctime',
            {'fields': ['realm_id', 'revision_no'], 'unique': True},
        ],
    }


class AuthRealmRevision(Document):
    """Immutable endpoint and protocol configuration for an AuthRealm."""
    realm_revision_id = StringField(required=True, unique=True)
    realm_id = StringField(required=True)
    revision_no = IntField(required=True)
    adapter_version_id = StringField(required=True)
    secret_version_id = StringField()
    auth_origins = ListField(StringField(), required=True)
    tls_verify = BooleanField(default=True)
    config = DictField()
    config_sha256 = StringField(required=True)
    lifecycle = StringField(default="draft")
    ctime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'authRealmRevision',
        'indexes': [
            'realm_revision_id', 'realm_id', 'adapter_version_id',
            'secret_version_id', 'lifecycle',
            {'fields': ['realm_id', 'revision_no'], 'unique': True},
            {'fields': ['realm_id', 'config_sha256'], 'unique': True},
        ],
    }


class ProjectAccountBinding(Document):
    """Bind a project-local alias to a stable TestAccount.

    ``env_id`` and ``account`` remain readable only for the one-time P0-B
    migration.  New authentication code resolves ``account_id`` and does not
    use the legacy SsoAccount reference.
    """
    project_id = StringField(required=True)
    env_id = StringField()
    account_key = StringField(required=True)
    account_id = StringField()
    account = ReferenceField(SsoAccount)
    display_name = StringField()
    role = StringField(default="test")
    is_test_account = BooleanField(default=True)
    active = BooleanField(default=True)
    metadata = DictField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    mtime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'projectAccountBinding',
        'indexes': [
            'project_id', 'env_id', 'account_key', 'account_id', 'role', 'active',
            {'fields': ['project_id', 'account_key'], 'unique': True},
        ],
    }


class ProjectAuthProfile(Document):
    """Stable selectable auth profile; executable details live in a revision."""
    profile_id = StringField(required=True, unique=True)
    project_id = StringField(required=True)
    env_id = StringField(required=True)
    account_key = StringField(required=True)
    name = StringField(required=True)
    purpose = StringField(default="default")
    lifecycle = StringField(default="active")
    current_revision_id = StringField()
    provider_id = StringField(required=True)
    context_ref = StringField()
    auth_kind = StringField(default="mixed")
    refresh_strategy = StringField(default="login")
    allowed_hosts = ListField(StringField())
    is_default = BooleanField(default=False)
    active = BooleanField(default=True)
    last_refresh_at = DateTimeField()
    last_error_type = StringField()
    metadata = DictField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    mtime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'projectAuthProfile',
        'indexes': [
            'project_id', 'env_id', 'account_key',
            'provider_id', 'purpose', 'lifecycle', 'active', 'is_default',
            {'fields': ['project_id', 'env_id', 'purpose', 'name'], 'unique': True},
            {
                'fields': ['project_id', 'env_id', 'purpose', 'is_default'],
                'unique': True,
                'partialFilterExpression': {'is_default': True, 'lifecycle': 'active'},
            },
        ],
    }


class ProjectAuthProfileRevision(Document):
    """Immutable executable revision pinned by snapshots and runs."""
    profile_revision_id = StringField(required=True, unique=True)
    profile_id = StringField(required=True)
    revision_no = IntField(required=True)
    project_account_key = StringField(required=True)
    realm_revision_id = StringField(required=True)
    auth_kind = StringField(default="mixed")
    refresh_strategy = StringField(default="login")
    allowed_business_origins = ListField(StringField())
    max_age_seconds = IntField(default=1800)
    config_sha256 = StringField(required=True)
    ctime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'projectAuthProfileRevision',
        'indexes': [
            'profile_revision_id', 'profile_id', 'realm_revision_id',
            {'fields': ['profile_id', 'revision_no'], 'unique': True},
            {'fields': ['profile_id', 'config_sha256'], 'unique': True},
        ],
    }


class AuthorizationPrincipal(Document):
    """Immutable project-local identity descriptor used by authorization policies."""
    principal_id = StringField(required=True, unique=True)
    project_id = StringField(required=True)
    env_id = StringField(required=True)
    profile_id = StringField(required=True)
    account_key = StringField(required=True)
    name = StringField(required=True)
    role_key = StringField()
    privilege_rank = IntField(default=0)
    scope_key = StringField()
    labels = ListField(StringField())
    attributes = DictField()
    active = BooleanField(default=True)
    ctime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'authorizationPrincipal',
        'indexes': [
             'project_id', 'env_id', 'profile_id', 'role_key',
             'privilege_rank', 'scope_key', 'active',
             {'fields': ['project_id', 'env_id', 'name'], 'unique': True},
             {'fields': ['project_id', 'env_id', 'profile_id'], 'unique': True},
         ],
    }


class AuthorizationPolicy(Document):
    """Immutable version of one logical authorization-matrix policy."""
    DRAFT = "draft"
    ACTIVE = "active"
    ARCHIVED = "archived"

    policy_key = StringField(required=True)
    policy_version_id = StringField(required=True, unique=True)
    project_id = StringField(required=True)
    env_id = StringField(required=True)
    name = StringField(required=True)
    version = IntField(required=True, default=1)
    lifecycle = StringField(default=DRAFT)
    principal_ids = ListField(StringField())
    principal_snapshots = ListField(DictField())
    resource_family = StringField()
    action = StringField(default="read")
    relation_ids = ListField(StringField())
    relation_snapshots = ListField(DictField())
    default_decision = StringField(default="review")
    same_principal_decision = StringField(default="allow")
    include_self = BooleanField(default=True)
    case_budget = IntField(default=100)
    request_budget_per_case = IntField(default=3)
    parent_policy_version_id = StringField()
    created_by = StringField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    activated_at = DateTimeField()

    meta = {
        'collection': 'authorizationPolicy',
        'indexes': [
            'policy_key', 'project_id', 'env_id', 'lifecycle', 'resource_family', 'action',
            {'fields': ['policy_key', 'version'], 'unique': True},
            {
                'fields': ['policy_key', 'lifecycle'],
                'unique': True,
                'partialFilterExpression': {'lifecycle': 'active'},
            },
        ],
    }


class AuthorizationPolicyRule(Document):
    """Selector-based expectation rule for one immutable policy version."""
    rule_id = StringField(required=True, unique=True)
    policy_version_id = StringField(required=True)
    priority = IntField(default=100)
    subject_selector = DictField()
    owner_selector = DictField()
    scope_relation = StringField(default="any")
    resource_family = StringField()
    action = StringField(default="read")
    expected_decision = StringField(required=True)
    reason_codes = ListField(StringField())
    description = StringField()
    active = BooleanField(default=True)
    ctime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'authorizationPolicyRule',
        'indexes': ['policy_version_id', '-priority', 'scope_relation', 'action', 'active'],
    }


class AuthorizationMatrixCase(Document):
    """One resource-owner x subject observation within a matrix run."""
    case_key = StringField(required=True)
    observation_key = StringField(required=True, unique=True)
    run_id = ObjectIdField(required=True)
    result_id = ObjectIdField()
    policy_key = StringField(required=True)
    policy_version_id = StringField(required=True)
    policy_version = IntField(required=True)
    project_id = StringField(required=True)
    env_id = StringField()
    resource_owner_principal_id = StringField(required=True)
    subject_principal_id = StringField(required=True)
    resource_family = StringField()
    action = StringField()
    expected_decision = StringField(required=True)
    observed_decision = StringField()
    matched_rule_id = StringField()
    reason_codes = ListField(StringField())
    ctime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'authorizationMatrixCase',
        'indexes': [
            'case_key', 'run_id', 'policy_key', 'policy_version_id', 'project_id', 'resource_family',
            'expected_decision', 'observed_decision',
            'resource_owner_principal_id', 'subject_principal_id', '-ctime',
        ],
    }


class AuthProfileHealth(Document):
    """Rebuildable current health projection for one profile revision."""
    profile_revision_id = StringField(required=True, unique=True)
    profile_id = StringField(required=True)
    status = StringField(default="unknown")
    stage = StringField()
    error_code = StringField()
    error_summary = StringField()
    last_attempt_id = StringField()
    last_verified_at = DateTimeField()
    updated_at = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'authProfileHealth',
        'indexes': ['profile_revision_id', 'profile_id', 'status', '-updated_at'],
    }


class AuthVerificationAttempt(Document):
    """Bounded, append-only, secret-free authentication verification."""
    attempt_id = StringField(required=True, unique=True)
    profile_id = StringField(required=True)
    profile_revision_id = StringField(required=True)
    realm_revision_id = StringField(required=True)
    adapter_version_id = StringField(required=True)
    status = StringField(default="running")
    stage = StringField(default="preflight")
    request_count = IntField(default=0)
    max_requests = IntField(default=3)
    error_code = StringField()
    error_summary = StringField()
    diagnostics = ListField(DictField())
    is_candidate = BooleanField(default=False)
    repair_candidate_id = StringField()
    previous_profile_revision_id = StringField()
    started_at = DateTimeField(default=datetime.datetime.utcnow)
    finished_at = DateTimeField()
    expires_at = DateTimeField()

    meta = {
        'collection': 'authVerificationAttempt',
        'indexes': [
            'attempt_id', 'profile_id', 'profile_revision_id',
            'repair_candidate_id', 'status', '-started_at',
            {'fields': ['expires_at'], 'expireAfterSeconds': 0},
        ],
    }


class AuthRepairCandidate(Document):
    """Append-only pointer set for one immutable authentication repair.

    The recipe, Realm, and Profile payloads live in their normal immutable
    version collections.  This record only coordinates candidate validation,
    activation, and an optional zero-progress paused-run rebind.
    """
    DRAFT = "draft"
    VALIDATING = "validating"
    FAILED = "failed"
    ACTIVATED = "activated"
    STALE = "stale"

    candidate_id = StringField(required=True, unique=True)
    profile_id = StringField(required=True)
    project_id = StringField(required=True)
    env_id = StringField(required=True)
    previous_profile_revision_id = StringField(required=True)
    candidate_profile_revision_id = StringField(required=True)
    candidate_realm_revision_id = StringField(required=True)
    candidate_adapter_version_id = StringField(required=True)
    status = StringField(default=DRAFT)
    reason = StringField()
    operator = StringField()
    verification_attempt_id = StringField()
    failure_code = StringField()
    resume_run_id = StringField()
    rebind_status = StringField()
    activation_summary = DictField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    mtime = DateTimeField(default=datetime.datetime.utcnow)
    activated_at = DateTimeField()

    meta = {
        'collection': 'authRepairCandidate',
        'indexes': [
            'candidate_id', 'profile_id', 'project_id', 'env_id',
            'previous_profile_revision_id', 'candidate_profile_revision_id',
            'status', '-ctime',
        ],
    }


class AuthMigrationRecord(Document):
    """Idempotent P0-B migration journal without credential values."""
    migration_key = StringField(required=True, unique=True)
    source_type = StringField(required=True)
    source_id = StringField(required=True)
    target_type = StringField(required=True)
    target_id = StringField(required=True)
    status = StringField(default="done")
    summary = DictField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'authMigrationRecord',
        'indexes': ['migration_key', 'source_type', 'source_id', 'target_type', 'target_id'],
    }


class ProjectRequestFixture(Document):
    """Reusable non-auth test inputs for one endpoint/account context.

    Authentication stays in ProjectAuthProfile/AccountContext.  The fixture
    supplies business fields that documentation, traffic samples and parameter
    relations could not determine reliably.
    """
    ACTIVE = "active"
    INACTIVE = "inactive"
    ARCHIVED = "archived"

    fixture_id = StringField(required=True, unique=True)
    project_id = StringField(required=True)
    env_id = StringField(required=True)
    pathid = IntField(required=True)
    profile_id = StringField()
    name = StringField(default="default")
    query = DictField()
    headers = DictField()
    path_params = DictField()
    body = BaseField()
    note = StringField()
    active = BooleanField(default=True)
    lifecycle = StringField(default=ACTIVE)
    current_revision_id = StringField()
    current_revision_no = IntField(default=0)
    payload_sha256 = StringField()
    modificator = StringField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    mtime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'projectRequestFixture',
        'indexes': [
            'project_id', 'env_id', 'pathid', 'profile_id', 'active',
            {
                'fields': ['project_id', 'env_id', 'pathid', 'profile_id', 'name'],
                'unique': True,
            },
        ],
    }


class ProjectRequestFixtureRevision(Document):
    """Immutable, non-auth business-input revision."""
    fixture_revision_id = StringField(required=True, unique=True)
    fixture_id = StringField(required=True)
    revision_no = IntField(required=True)
    payload_sha256 = StringField(required=True)
    query = DictField()
    headers = DictField()
    path_params = DictField()
    body = BaseField()
    note = StringField()
    created_by = StringField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'projectRequestFixtureRevision',
        'indexes': [
            'fixture_id', 'payload_sha256', '-ctime',
            {'fields': ['fixture_id', 'revision_no'], 'unique': True},
            {'fields': ['fixture_id', 'payload_sha256'], 'unique': True},
        ],
    }


class ProjectRequestFixtureEvent(Document):
    CREATED = "created"
    REVISED = "revised"
    ACTIVATED = "activated"
    DEACTIVATED = "deactivated"
    ARCHIVED = "archived"

    fixture_id = StringField(required=True)
    fixture_revision_id = StringField()
    event_type = StringField(required=True)
    from_lifecycle = StringField()
    to_lifecycle = StringField()
    actor = StringField()
    reason = StringField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'projectRequestFixtureEvent',
        'indexes': ['fixture_id', 'fixture_revision_id', 'event_type', '-ctime'],
    }


class ImportRun(Document):
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"

    import_run_id = StringField(required=True, unique=True)
    contract_version = StringField(default="1")
    data_source_id = StringField()
    project_id = StringField()
    project_ids = ListField(StringField())
    source_type = StringField(required=True)
    source_id = StringField()
    env_id = StringField()
    account_id = StringField()
    content_hash = StringField()
    status = StringField(default=RUNNING)
    summary = DictField()
    error_summary = StringField()
    started_at = DateTimeField(default=datetime.datetime.utcnow)
    finished_at = DateTimeField()

    meta = {
        'collection': 'importRun',
        'indexes': [
            'import_run_id', 'data_source_id', 'project_id', 'source_type',
            'status', '-started_at',
        ],
    }


class RequestObservation(Document):
    """Sanitized immutable observation from Workspace, HAR, browser, or replay."""
    observation_id = StringField(required=True, unique=True)
    data_source_id = StringField()
    source_type = StringField(required=True)
    source_id = StringField()
    workspace_id = StringField()
    import_run_id = StringField()
    account_id = StringField()
    env_id = StringField()
    method = StringField(required=True)
    url = StringField(required=True)
    domain = StringField()
    path = StringField(required=True)
    abstract_signature = StringField()
    content_hash = StringField()
    request_metadata = DictField()
    response_metadata = DictField()
    sample_id = StringField()
    captured_at = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'requestObservation',
        'indexes': [
            'observation_id', 'data_source_id', 'source_type', 'workspace_id',
            'abstract_signature', 'domain', '-captured_at',
        ],
    }


class ObservationRoutingDecision(Document):
    ASSIGNED = "assigned"
    AMBIGUOUS = "ambiguous"
    UNASSIGNED = "unassigned"
    IGNORED = "ignored"

    observation_id = StringField(required=True)
    selected_project_id = StringField()
    selected_env_id = StringField()
    candidate_projects = ListField(DictField())
    confidence = FloatField(default=0.0)
    reason_codes = ListField(StringField())
    decision = StringField(required=True)
    rule_version = StringField(default="v1")
    manual_by = StringField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'observationRoutingDecision',
        'indexes': ['observation_id', 'selected_project_id', 'decision', '-ctime'],
    }


class ProjectAssetLink(Document):
    project_id = StringField(required=True)
    pathid = IntField(required=True)
    relationship = StringField(default="owned")
    env_id = StringField()
    confidence = FloatField(default=1.0)
    reason_codes = ListField(StringField())
    observation_ids = ListField(StringField())
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    mtime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'projectAssetLink',
        'indexes': [
            'project_id', 'pathid', 'relationship',
            {'fields': ['project_id', 'pathid', 'env_id'], 'unique': True},
        ],
    }


class raw_data(Document):
    _id = ObjectIdField(primary_key=True)
    source = StringField()
    source_id = StringField()
    source_meta = DictField()
    project_id = StringField()
    env_id = StringField()
    import_run_id = StringField()
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
    class_score_contributions = ListField(DictField())
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
            'project_id',
            'env_id',
            'import_run_id',
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
    direction = StringField(default="request")
    raw_path = StringField()
    schema_path = StringField()
    display_path = StringField()
    canonical_name = StringField()
    locator = DictField()
    relation = StringField()
    Priority = IntField()
    value = ListField()
    required = BooleanField()
    type = StringField()
    des = StringField()
    modificator = StringField()
    meta = {
        'collection': 'reqParseData',
        'indexes': ['position', 'canonical_name', 'schema_path'],
    }


class res_data(Document):
    raw_data = ReferenceField(raw_data, required=True)
    source_meta = DictField()
    Content_type = StringField()
    parameter = StringField()
    direction = StringField(default="response")
    raw_path = StringField()
    schema_path = StringField()
    display_path = StringField()
    canonical_name = StringField()
    locator = DictField()
    value = ListField()
    type = StringField()
    des = StringField()
    position = StringField()
    relation = StringField()
    modificator = StringField()
    meta = {
        'collection': 'resParseData',
        'indexes': ['position', 'canonical_name', 'schema_path'],
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
    # Legacy parameterData ids are retained when known.  Profile-scoped facts
    # are keyed by typed locator/identity and must not invent a global id just
    # because an Apifox-only field has no parameterData row.
    parameterid = ListField()
    #parameter_value = IntField()
    req_pathid = ListField()
    res_pathid = ListField()
    req_value = ListField()
    res_value = ListField()
    properties = ListField()
    modificator = StringField()
    account_id = StringField()
    project_id = StringField()
    env_id = StringField()
    # Optional provenance for archives built from concrete, account-bound
    # request samples.  Legacy rows intentionally remain unlabelled and must
    # not be treated as immutable Profile-scoped rule evidence.
    profile_revision_id = StringField()
    source_kind = StringField()
    source_watermark_sha256 = StringField()
    meta = {
        'collection': 'parameterArchive',
        'indexes': [
            'project_id', 'env_id', 'account_id', 'profile_revision_id', 'source_kind',
        ],
    }

class parameter_relation(Document):
    parameter = StringField(required=True)
    source_parameter = StringField()
    target_parameter = StringField()
    source_position = StringField(default="body")
    target_position = StringField()
    source_locator = DictField()
    target_locator = DictField()
    locator_version = IntField(default=2)
    location_status = StringField(default="pending")
    location_note = StringField()
    req_pathid = IntField(required=True)
    res_pathid = IntField(required=True)
    rule = StringField()
    relation = StringField()
    score = FloatField()
    reason_codes = ListField(StringField())
    evidence = ListField()
    verified = BooleanField(default=False)
    modificator = StringField()
    manual_decision = StringField()
    manual_note = StringField()
    feedback_status = StringField()
    feedback_note = StringField()
    # Machine preprocessing is deliberately separate from manual feedback.
    # Priority is a derived work queue; these fields describe whether this
    # concrete source -> consumer edge can be validated automatically.
    preprocess_version = StringField()
    preprocess_status = StringField(default="pending")
    preprocess_reason_codes = ListField(StringField())
    preprocess_summary = DictField()
    machine_confidence = FloatField(default=0.0)
    estimated_requests = IntField(default=0)
    selected_source_host = StringField()
    selected_consumer_host = StringField()
    approval_status = StringField(default="not_required")
    approval_by = StringField()
    approval_at = DateTimeField()
    last_preprocessed_at = DateTimeField()
    last_validation_run_id = ObjectIdField()
    # Project-scoped incremental discovery metadata.  A confirmed relation is
    # never overwritten by a later import; schema drift marks it stale while
    # retaining the last confirmed fingerprint and all runtime/manual evidence.
    discovery_version = StringField()
    discovery_source = StringField()
    evidence_sources = ListField(StringField())
    schema_fingerprint = StringField()
    confirmed_schema_fingerprint = StringField()
    stale_reason = StringField()
    first_seen_at = DateTimeField()
    last_seen_at = DateTimeField()
    project_id = StringField()
    env_id = StringField()
    mtime = DateTimeField(default=datetime.datetime.utcnow)
    meta = {
        'collection': 'parameterRelation',
        'indexes': [
            'project_id', 'env_id', 'location_status', 'preprocess_status',
            'approval_status', 'discovery_source', '-last_preprocessed_at',
        ],
    }


class parameter_relation_analysis_run(Document):
    """Durable, local-only full-project relation preprocessing job."""

    STATUS_QUEUED = "queued"
    STATUS_RUNNING = "running"
    STATUS_DONE = "done"
    STATUS_FAILED = "failed"
    STATUS_CANCEL_REQUESTED = "cancel_requested"
    STATUS_CANCELLED = "cancelled"
    ACTIVE_STATUSES = (
        STATUS_QUEUED,
        STATUS_RUNNING,
        STATUS_CANCEL_REQUESTED,
    )

    project_id = StringField(required=True)
    env_id = StringField()
    source_profile_id = StringField()
    consumer_profile_id = StringField()
    analysis_version = StringField()
    profile_revision_id = StringField()
    rule_bundle_sha256 = StringField()
    input_watermark_sha256 = StringField()
    status = StringField(default=STATUS_QUEUED)
    phase = StringField(default="queued")
    total_relations = IntField(default=0)
    processed_relations = IntField(default=0)
    status_counts = DictField()
    discovery_summary = DictField()
    rule_summary = DictField()
    comparison_summary = DictField()
    persistence_summary = DictField()
    plan_draft_summary = DictField()
    result_summary = DictField()
    cursor_relation_id = ObjectIdField()
    cursor_phase = StringField()
    cursor_key = StringField()
    operator = StringField()
    worker_id = StringField()
    lease_expires_at = DateTimeField()
    error_type = StringField()
    error_reference = StringField()
    created_at = DateTimeField(default=datetime.datetime.utcnow)
    started_at = DateTimeField()
    updated_at = DateTimeField(default=datetime.datetime.utcnow)
    finished_at = DateTimeField()

    meta = {
        "collection": "parameterRelationAnalysisRun",
        "indexes": [
            "project_id",
            "env_id",
            "status",
            "analysis_version",
            "rule_bundle_sha256",
            "-updated_at",
            "lease_expires_at",
        ],
    }


class parameter_validation_result(Document):
    parameter = StringField(required=True)
    group_key = StringField()
    relation = ReferenceField(parameter_relation)
    project_id = StringField()
    env_id = StringField()
    run_id = ObjectIdField()
    execution_result_id = ObjectIdField()
    case_key = StringField()
    req_pathid = IntField()
    res_pathid = IntField()
    status = StringField()
    value_source = StringField()
    used_value = BaseField()
    extracted_values = ListField(BaseField())
    value_digest = StringField()
    value_type = StringField()
    value_length = IntField(default=0)
    target_position = StringField()
    source_profile_id = StringField()
    consumer_profile_id = StringField()
    source_host = StringField()
    consumer_host = StringField()
    source_snapshot_id = StringField()
    consumer_snapshot_id = StringField()
    source_result = DictField()
    consumer_result = DictField()
    note = StringField()
    manual_by = StringField()
    pinned = BooleanField(default=False)
    expires_at = DateTimeField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    meta = {
        'collection': 'parameterValidationResult',
        'indexes': [
            'parameter',
            'group_key',
            'req_pathid',
            'res_pathid',
            'run_id',
            'project_id',
            'env_id',
            '-ctime',
            {'fields': ['case_key'], 'unique': True, 'sparse': True},
            {'fields': ['expires_at'], 'expireAfterSeconds': 0},
        ]
    }


class parameter_priority_review(Document):
    project_id = StringField()
    parameter = StringField(required=True)
    manual_role = StringField()
    manual_weight = FloatField()
    manual_note = StringField()
    ai_role = StringField()
    ai_weight = FloatField()
    ai_note = StringField()
    reviewer = StringField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    mtime = DateTimeField(default=datetime.datetime.utcnow)
    meta = {
        'collection': 'parameterPriorityReview',
        'indexes': [
            'project_id',
            'parameter',
            {'fields': ['project_id', 'parameter'], 'unique': True},
        ]
    }


class parameter_priority_item(Document):
    project_id = StringField(required=True)
    parameter = StringField(required=True)
    canonical_key = StringField()
    aliases = ListField(StringField())
    raw_paths = ListField(StringField())
    normalization_version = StringField()
    rule_role = StringField()
    rule_weight = FloatField()
    rule_reasons = ListField(StringField())
    doc_count = IntField(default=0)
    request_doc_count = IntField(default=0)
    response_doc_count = IntField(default=0)
    endpoint_count = IntField(default=0)
    relation_count = IntField(default=0)
    candidate_count = IntField(default=0)
    readiness_score = FloatField(default=0.0)
    readiness_status = StringField(default="unknown")
    readiness_reasons = ListField(StringField())
    work_priority = FloatField(default=0.0)
    # Usage is based on bounded real traffic samples, never documentation row
    # count.  composite_score combines business importance with observed use;
    # documentation-only projects fall back to importance instead of inventing
    # a traffic frequency.
    usage_count = IntField(default=0)
    usage_score = FloatField(default=0.0)
    composite_score = FloatField(default=0.0)
    usage_sources = DictField()
    last_observed_at = DateTimeField()
    sample_docs = ListField(DictField())
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    mtime = DateTimeField(default=datetime.datetime.utcnow)
    meta = {
        'collection': 'parameterPriorityItem',
        'indexes': [
            'project_id',
            'parameter',
            'canonical_key',
            'rule_role',
            '-rule_weight',
            '-composite_score',
            '-usage_score',
            {'fields': ['project_id', 'parameter'], 'unique': True},
        ]
    }


class parameter_experience(Document):
    project_id = StringField(required=True)
    parameter = StringField(required=True)
    group_key = StringField()
    process_status = StringField(default="needs_review")
    role = StringField(default="unknown")
    scope_type = StringField(default="project")
    scope_value = StringField()
    business_meaning = StringField()
    reuse_policy = StringField(default="unknown")
    chain_policy = StringField(default="unknown")
    validation_policy = StringField(default="needs_verify")
    confidence = FloatField(default=0.0)
    manual_note = StringField()
    ai_note = StringField()
    reviewer = StringField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    mtime = DateTimeField(default=datetime.datetime.utcnow)
    meta = {
        'collection': 'parameterExperience',
        'indexes': [
            'project_id',
            'parameter',
            'group_key',
            'process_status',
            'role',
            {'fields': ['project_id', 'parameter', 'group_key'], 'unique': True},
        ]
    }


class interface_chain_feedback(Document):
    project_id = StringField()
    env_id = StringField()
    family = StringField(required=True)
    strategy = StringField()
    evidence_tier = StringField()
    decision = StringField()
    blocker_class = StringField()
    confidence = FloatField()
    note = StringField()
    missing_data = StringField()
    source_file = StringField()
    latest_validation_status = StringField()
    latest_validation_reasons = ListField(StringField())
    manual_by = StringField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    mtime = DateTimeField(default=datetime.datetime.utcnow)
    meta = {
        'collection': 'interfaceChainFeedback',
        'indexes': [
            'project_id',
            'decision',
            'blocker_class',
            'evidence_tier',
            {'fields': ['project_id', 'env_id', 'family'], 'unique': True, 'name': 'project_env_family_unique'},
        ]
    }


class idor_parameter_candidate(Document):
    """
    Endpoint-scoped parameter role used by IDOR construction.

    parameter_archive stores raw observed values. This collection stores the
    security meaning of a parameter for one endpoint so later tests know which
    values can be replayed, swapped, or must be kept as auth/context.
    """
    pathid = IntField(required=True)
    project_id = StringField()
    env_id = StringField()
    raw_data = ReferenceField(raw_data)
    method = StringField()
    path = StringField()
    parameter = StringField(required=True)
    canonical_name = StringField()
    direction = StringField(default="request")
    position = StringField()
    schema_path = StringField()
    locator = DictField()
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
            'canonical_name',
            'direction',
            'schema_path',
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
    resource_owner_principal_id = StringField()
    subject_principal_id = StringField()
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
    contract_version = StringField(default="1")
    raw_data = ReferenceField(raw_data)
    source = StringField(default="asset")
    project_id = StringField()
    import_run_id = StringField()
    env_id = StringField()
    account_id = StringField()
    auth_mode = StringField(default="inherit")
    auth_provider_id = StringField()
    auth_context_ref = StringField()
    auth_profile_revision_id = StringField()
    auth_realm_revision_id = StringField()
    auth_adapter_version_id = StringField()
    plan_version = StringField()
    plan_sha256 = StringField()
    adapter_id = StringField()
    adapter_version = StringField()
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
    template_key = StringField()
    expires_at = DateTimeField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'requestSnapshot',
        'indexes': [
            'pathid',
            'source',
            'project_id',
            'import_run_id',
            'env_id',
            'account_id',
            'auth_provider_id',
            'auth_profile_revision_id',
            '-ctime',
            {'fields': ['template_key'], 'unique': True, 'sparse': True},
            {'fields': ['expires_at'], 'expireAfterSeconds': 0},
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
    project_id = StringField()
    import_run_id = StringField()
    observation_id = StringField()
    env_id = StringField()
    account_id = StringField()
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
            'project_id',
            'import_run_id',
            'sample_signature',
            '-last_seen',
            {'fields': ['raw_data', 'sample_signature'], 'unique': True},
        ]
    }


class security_test_run(Document):
    """
    One bounded security test execution batch.

    Store only sanitized metadata here. Credentials, raw response bodies, real
    resource ids, and full private evidence should remain in local private files
    referenced by evidence_ref.
    """
    PREPARING = "preparing"
    QUEUED = "queued"
    RUNNING = "running"
    CANCEL_REQUESTED = "cancel_requested"
    CANCELLED = "cancelled"
    PAUSED = "paused"
    DONE = "done"
    FAILED = "failed"

    name = StringField(required=True)
    contract_version = StringField(default="1")
    profile_id = StringField()
    project_id = StringField()
    env_id = StringField()
    account_id = StringField()
    auth_mode = StringField(default="inherit")
    auth_provider_id = StringField()
    auth_context_ref = StringField()
    auth_context_summary = DictField()
    auth_profile_revision_id = StringField()
    auth_realm_revision_id = StringField()
    auth_adapter_version_id = StringField()
    adapter_id = StringField()
    adapter_version = StringField()
    plan_version = StringField()
    plan_sha256 = StringField()
    parent_run_id = ObjectIdField()
    retry_of_run_id = ObjectIdField()
    check_type = StringField(required=True)
    scope = DictField()
    source = StringField(default="manual")
    status = StringField(required=True, default=RUNNING)
    summary = DictField()
    evidence_ref = StringField()
    scheduler_managed = BooleanField(default=False)
    idempotency_key = StringField()
    queue_name = StringField(default="snapshot")
    priority = IntField(default=100)
    snapshot_ids = ListField(ObjectIdField())
    execution_policy = DictField()
    total_cases = IntField(default=0)
    pending_cases = IntField(default=0)
    running_cases = IntField(default=0)
    completed_cases = IntField(default=0)
    failed_cases = IntField(default=0)
    skipped_cases = IntField(default=0)
    cancelled_cases = IntField(default=0)
    dispatch_attempt = IntField(default=0)
    max_dispatch_attempts = IntField(default=3)
    lease_owner = StringField()
    lease_token = StringField()
    lease_expires_at = DateTimeField()
    heartbeat_at = DateTimeField()
    queued_at = DateTimeField()
    updated_at = DateTimeField(default=datetime.datetime.utcnow)
    cancel_reason = StringField()
    last_error_type = StringField()
    pause_code = StringField()
    dependency_type = StringField()
    dependency_id = StringField()
    dependency_revision_id = StringField()
    host_state = DictField()
    started_at = DateTimeField(default=datetime.datetime.utcnow)
    finished_at = DateTimeField()
    operator = StringField()
    notes = StringField()
    expires_at = DateTimeField()

    meta = {
        'collection': 'securityTestRun',
        'indexes': [
            'profile_id',
            'project_id',
            'env_id',
            'auth_provider_id',
            'auth_profile_revision_id',
            'adapter_id',
            'plan_version',
            'check_type',
            'status',
            'dependency_type',
            'dependency_id',
            'scheduler_managed',
            'queue_name',
            'priority',
            'lease_expires_at',
            '-started_at',
            {'fields': ['idempotency_key'], 'unique': True, 'sparse': True},
            {'fields': ['scheduler_managed', 'queue_name', 'status', '-priority', 'queued_at']},
            {'fields': ['scheduler_managed', 'status', 'lease_expires_at']},
            {'fields': ['expires_at'], 'expireAfterSeconds': 0},
        ]
    }


class security_execution_checkpoint(Document):
    """Small resumable execution state for one snapshot in a scheduled run.

    This is intentionally not a second result model. It contains only runtime
    progress and sanitized outcome metadata; conclusions remain in
    security_test_result and private response bodies remain outside Mongo.
    """
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"

    run_id = ObjectIdField(required=True)
    snapshot_id = ObjectIdField(required=True)
    project_id = StringField()
    env_id = StringField()
    pathid = IntField()
    ordinal = IntField(required=True)
    host = StringField()
    status = StringField(required=True, default=PENDING)
    attempt_count = IntField(default=0)
    lease_token = StringField()
    result_id = ObjectIdField()
    reason_codes = ListField(StringField())
    outcome_summary = DictField()
    error_type = StringField()
    started_at = DateTimeField()
    finished_at = DateTimeField()
    updated_at = DateTimeField(default=datetime.datetime.utcnow)
    expires_at = DateTimeField()

    meta = {
        'collection': 'securityExecutionCheckpoint',
        'indexes': [
            'run_id',
            'snapshot_id',
            'project_id',
            'host',
            'status',
            {'fields': ['run_id', 'snapshot_id'], 'unique': True},
            {'fields': ['run_id', 'status', 'ordinal']},
            {'fields': ['expires_at'], 'expireAfterSeconds': 0},
        ]
    }


class security_test_result(Document):
    """
    Sanitized conclusion for one security test case within a run.
    """
    run_id = ObjectIdField(required=True)
    contract_version = StringField(default="1")
    execution_key = StringField()
    project_id = StringField()
    env_id = StringField()
    account_id = StringField()
    auth_mode = StringField()
    auth_provider_id = StringField()
    snapshot_id = ObjectIdField()
    case_name = StringField(required=True)
    check_type = StringField(required=True)
    target = DictField()
    method = StringField()
    verdict = StringField(required=True)
    outcome_class = StringField()
    priority = StringField()
    severity = StringField()
    confidence = FloatField()
    reason_codes = ListField(StringField())
    evidence_summary = DictField()
    evidence_ref = StringField()
    related_pathid = IntField()
    related_vuln_id = ObjectIdField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    expires_at = DateTimeField()

    meta = {
        'collection': 'securityTestResult',
        'indexes': [
            'run_id',
            'check_type',
            'verdict',
            'outcome_class',
            'priority',
            'related_pathid',
            '-ctime',
            {'fields': ['execution_key'], 'unique': True, 'sparse': True},
            {'fields': ['expires_at'], 'expireAfterSeconds': 0},
        ]
    }


class security_test_plan(Document):
    """
    Versioned test plan: one explicit interface scope, policy version,
    account roles and budget. Plans are project-scoped and immutable
    once activated; edits create a new version.
    """
    DRAFT = "draft"
    ACTIVE = "active"
    ARCHIVED = "archived"

    name = StringField(required=True)
    project_id = StringField(required=True)
    env_id = StringField()
    version = IntField(default=1)
    status = StringField(default=DRAFT)
    check_type = StringField(required=True)
    adapter_id = StringField()
    adapter_version = StringField()
    auth_mode = StringField(default="inherit")
    auth_profile_id = StringField()
    scope = DictField()
    execution_policy = DictField()
    snapshot_filter = DictField()
    request_budget = IntField()
    description = StringField()
    created_by = StringField()
    parent_plan_id = ObjectIdField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    updated_at = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'securityTestPlan',
        'indexes': [
            'project_id',
            'env_id',
            'check_type',
            'status',
            '-ctime',
            {'fields': ['project_id', 'name', 'version'], 'unique': True},
        ]
    }


class result_review_event(Document):
    """
    Append-only human or rule disposition on a machine result.
    Machine results are never overwritten; all human decisions are
    recorded as independent review events.
    """
    CONFIRM = "confirm"
    REJECT = "reject"
    NEED_MORE_EVIDENCE = "need_more_evidence"
    DUPLICATE = "duplicate"
    ESCALATE = "escalate"
    COMMENT = "comment"

    result_id = ObjectIdField(required=True)
    run_id = ObjectIdField()
    project_id = StringField()
    action = StringField(required=True)
    reviewer = StringField(required=True)
    reviewer_role = StringField()
    reason = StringField()
    reason_codes = ListField(StringField())
    finding_id = ObjectIdField()
    duplicate_of_result_id = ObjectIdField()
    evidence_note = StringField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'resultReviewEvent',
        'indexes': [
            'result_id',
            'run_id',
            'project_id',
            'action',
            'finding_id',
            '-ctime',
        ]
    }


class vulnerability_finding(Document):
    """
    Stable vulnerability aggregation. References one or more machine
    results; machine results reference at most one current finding.
    """
    OPEN = "open"
    FIXING = "fixing"
    FIXED_PENDING_VERIFY = "fixed_pending_verify"
    VERIFIED_FIXED = "verified_fixed"
    REOPENED = "reopened"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"

    CLOSED_REASONS = (VERIFIED_FIXED, FALSE_POSITIVE, ACCEPTED_RISK)

    title = StringField(required=True)
    project_id = StringField(required=True)
    env_id = StringField()
    check_type = StringField()
    severity = StringField()
    confidence = FloatField()
    status = StringField(default=OPEN)
    close_reason = StringField()
    result_ids = ListField(ObjectIdField())
    run_ids = ListField(ObjectIdField())
    affected_endpoints = ListField(DictField())
    evidence_summary = DictField()
    evidence_ref = StringField()
    assigned_to = StringField()
    found_by = StringField()
    found_at = DateTimeField(default=datetime.datetime.utcnow)
    closed_at = DateTimeField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)
    updated_at = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'vulnerabilityFinding',
        'indexes': [
            'project_id',
            'env_id',
            'check_type',
            'status',
            'severity',
            'assigned_to',
            '-ctime',
        ]
    }


class finding_event(Document):
    """
    Append-only lifecycle event on a vulnerability finding: status
    transitions, comments, assignments, fix verification links.
    """
    CREATED = "created"
    STATUS_CHANGE = "status_change"
    ASSIGNED = "assigned"
    COMMENT = "comment"
    FIX_VERIFY = "fix_verify"
    REOPENED = "reopened"
    CLOSED = "closed"

    finding_id = ObjectIdField(required=True)
    event_type = StringField(required=True)
    from_status = StringField()
    to_status = StringField()
    actor = StringField(required=True)
    reason = StringField()
    reason_codes = ListField(StringField())
    related_run_id = ObjectIdField()
    related_result_ids = ListField(ObjectIdField())
    note = StringField()
    ctime = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'findingEvent',
        'indexes': [
            'finding_id',
            'event_type',
            '-ctime',
        ]
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
