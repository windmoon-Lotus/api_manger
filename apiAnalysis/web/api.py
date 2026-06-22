import uuid
from .. import users
from ..core.identify.sso import sso_account_record
from . import bp_api
from ..common.decorators import *
from ..core.lib import *
from ..db.collection import raw_data, api_version, vuln_record, test_case, privilege_task
from ..common.func import is_manager, format_request, format_response
from ..model.exception import *
from ..common.util import *
from flask import request, jsonify, session
from ..core.flow import watch_hosts


@bp_api.route("/watch", methods=['POST'])
@login_check
def site_parse():
    data = request.get_json()
    if not data:
        raise ApiException('Incorrect format!')

    if not data.get('site'):
        raise ApiException('请输入有效的站点！')
    current_url, system_type, hs, portal_site = watch_hosts(data['site'])

    return jsonify(Resp(Resp.SUCCESS, {
        'redirect_url': current_url,
        'system_type': system_type,
        'hs': ','.join(hs),
        'portal_site': portal_site,
    }))


@bp_api.route("/identify")
@login_check
def identify():
    """
    为该session中的唯一用户名生成一个唯一标识（每次都会重新标识）
    后面可通过该标识获取当前用户
    :return: [username, uid]
    """
    username = session.get('username')
    rs = redis.Redis(connection_pool=redis_pool)

    uid = uuid.uuid1().hex
    rs.hset("user_identify", username, uid)

    return jsonify(Resp(Resp.SUCCESS, [username, uid]))


@bp_api.route("/login", methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        raise ApiException("请求格式错误")

    user = users.get(data['username'])
    if not user or user.get('password') != data.get('password'):
        raise ApiException("账号或密码错误")
    session['username'] = data['username']
    session['role'] = user.get('role')
    return jsonify(Resp(Resp.SUCCESS))


@bp_api.route("/logout")
def logout():
    session.clear()
    return jsonify(Resp(Resp.SUCCESS))


@bp_api.route("/parse", methods=['POST'])
def req_parse():
    """
    接收请求，把要扫描的内容推入队列中
    :return:
    """
    uid = request.form.get('uid')  # 流量的所属人
    url = request.form.get('url')
    raw = request.form.get('raw')

    rs = redis.Redis(connection_pool=redis_pool)
    name = None
    for k, v in rs.hscan_iter("user_identify"):
        if v.decode('utf-8') == uid:
            name = k.decode('utf-8')
            break

    if not name:
        raise ApiException('identify error')
    logger.debug("parse {} {}".format(name, url))

    task = TaskModel(name, url, raw)
    rs.rpush("auth_session", json.dumps(task))

    return jsonify(Resp(Resp.SUCCESS))


# --------------------------- ↓ 流量 ↓-------------------------------------
@bp_api.route("/packetdata/<pd_id>")
@login_check
def packet_data(pd_id):
    """
    获取一个数据包的信息
    :param pd_id:
    :return:
    """
    pd = PacketData.objects(id=pd_id)
    if len(pd) != 1:
        raise ApiException("错误的数据包id: ".format(pd_id))
    pd = pd[0]
    assert isinstance(pd, PacketData)

    return jsonify(Resp(Resp.SUCCESS, {
        'banner': pd.banner,
        'describe': pd.role_describe,
        'req': format_request(pd.request),
        'resp': format_response(pd.response)
    }))


@bp_api.route("/replay/<pr_id>")
@login_check
def replay_traffic(pr_id):
    """
    流量重放 数据包id
    :param pr_id:
    :return:
    """
    pr = PacketRecord.objects(id=pr_id)
    if len(pr) == 0:
        raise ApiException("{} not found!".format(pr_id))
    pr = pr[0]
    assert isinstance(pr, PacketRecord)

    pr_replay(session.get('username'), pr)

    return jsonify(Resp(Resp.SUCCESS))


# --------------------------- ↑ 流量 ↑-------------------------------------


# --------------------------- ↓ 工作空间 ↓-------------------------------------
@bp_api.route("/workspace", methods=['PUT'])
@login_check
def workspace():
    """
    工作空间
    PUT: (新增）
    :return:
    """
    data = request.get_json()
    if not data:
        raise ApiException('Incorrect format!')

    depart_name = data.get('depart_name')
    system_name = data.get('system_name')

    if not depart_name or not system_name:
        raise ApiException("请输入部门和系统名!")

    ws = Workspace(depart_name=depart_name, cname=session['username'], system_name=system_name)
    ws.save()
    logger.info("workspace created: {}".format(ws.id))

    return jsonify(Resp(Resp.SUCCESS, str(ws.id)))


@bp_api.route("/workspace/<_id>", methods=['GET', 'DELETE'])
@login_check
def workspace_op(_id):
    """
    GET： 查询工作空间信息
    :param _id:
    :return:
    """

    if is_manager():
        ws = Workspace.objects(id=_id)
    else:
        ws = Workspace.objects(id=_id, cname=session['username'])
    if len(ws) == 0:
        raise ApiException("未找到对应的工作空间：".format(_id))
    ws = ws[0]
    assert isinstance(ws, Workspace)

    if request.method == 'GET':
        d = to_json(ws)
        d.update({
            'request_num': PacketRecord.objects(ws_id=_id).count()
        })
        return jsonify(Resp(Resp.SUCCESS, d))
    else:
        PacketRecord.objects(ws_id=ws.id).update(is_delete=True)
        rs = redis.Redis(connection_pool=redis_pool)
        rs.delete("parse_heap:{}:{}".format(session['username'], _id))
        return jsonify(Resp(Resp.SUCCESS))


@bp_api.route("/workspace/<_id>/config", methods=['PUT', 'GET'])
@login_check
def workspace_config(_id):
    """
    PUT: 配置工作空间
    GET: 获取工作空间配置
    :param _id:
    :return:
    """
    if request.method == 'GET':
        if is_manager():
            ws = Workspace.objects(id=_id)
        else:
            ws = Workspace.objects(id=_id, cname=session['username'])
        if len(ws) == 0:
            raise ApiException('未找到对应工作空间：{}'.format(_id))
        ws = ws[0]
        assert isinstance(ws, Workspace)
        data = to_json(ws)

        if ws.system_type == Workspace.TYPE_DIRECT:  # 手动认证
            auth = WorkspaceAuth.objects(ws_id=_id)
            if len(auth) != 0:
                data['roles'] = to_json(auth[0])
            else:
                data['roles'] = None
        else:  # sso认证
            sso = WorkspaceSso.objects(ws_id=_id)
            if len(sso) != 0:
                data['roles'] = to_json(sso[0])
            else:
                data['roles'] = None
        return jsonify(Resp(Resp.SUCCESS, data))

    if request.method == 'PUT':
        data = request.get_json()
        if not data:
            raise ApiException("请求不可空！")
        if not is_manager():
            ws = Workspace.objects(id=_id, cname=session['username'])
            if len(ws) == 0:
                raise ApiException("未找到对应工作空间：{}".format(_id))
        conf_workspace(_id, data)
        return jsonify(Resp(Resp.SUCCESS))


@bp_api.route("/rawdata", methods=['GET'])
@login_check
def rawdata_list():
    action = request.args.get('action')
    path = request.args.get('path')
    query = {}
    if action:
        query['action'] = action
    if path:
        query['path__regex'] = path
    hits = raw_data.objects(**query).order_by('-ptah_id').limit(100)
    return jsonify(Resp(Resp.SUCCESS, to_json(hits)))


@bp_api.route("/rawdata/<_id>", methods=['PUT'])
@login_check
def rawdata_update(_id):
    data = request.get_json()
    if not data:
        raise ApiException("Incorrect format!")
    update_fields = {}
    for key in ["action", "rule", "des", "tags", "modificator"]:
        if key in data:
            update_fields[key] = data[key]
    if not update_fields:
        raise ApiException("No valid fields to update")
    obj = raw_data.objects(id=_id).first()
    if not obj:
        raise ApiException("raw_data not found")
    for key, value in update_fields.items():
        setattr(obj, key, value)
    obj.save()
    return jsonify(Resp(Resp.SUCCESS))


@bp_api.route("/privilege/tasks", methods=['GET'])
@login_check
def privilege_tasks():
    scenario = request.args.get('scenario')
    status = request.args.get('status')
    final_result = request.args.get('final_result')
    limit = request.args.get('limit', default=100, type=int)
    if limit is None or limit <= 0:
        limit = 100
    if limit > 500:
        limit = 500

    query = {}
    if scenario:
        query['scenario'] = scenario
    if status:
        query['status'] = status
    if final_result:
        query['final_result'] = final_result

    hits = privilege_task.objects(**query).order_by('-id').limit(limit)
    stats = {
        "status_init": privilege_task.objects(status=privilege_task.STATUS_INIT).count(),
        "status_done": privilege_task.objects(status=privilege_task.STATUS_DONE).count(),
        "status_skip": privilege_task.objects(status=privilege_task.STATUS_SKIP).count(),
        "final_potential_vuln": privilege_task.objects(final_result="potential_vuln").count(),
        "final_need_review": privilege_task.objects(final_result="need_review").count(),
        "final_no_vuln": privilege_task.objects(final_result="no_vuln").count(),
    }
    return jsonify(Resp(Resp.SUCCESS, {"hits": to_json(hits), "stats": stats, "limit": limit}))


@bp_api.route("/version", methods=['GET', 'PUT'])
@login_check
def version_list():
    if request.method == 'GET':
        return jsonify(Resp(Resp.SUCCESS, to_json(api_version.objects())))
    data = request.get_json()
    if not data:
        raise ApiException("Incorrect format!")
    v = api_version(name=data.get('name'), version=data.get('version'), base_url=data.get('base_url'))
    v.save()
    return jsonify(Resp(Resp.SUCCESS, to_json(v)))


@bp_api.route("/version/<_id>", methods=['DELETE'])
@login_check
def version_delete(_id):
    api_version.objects(id=_id).delete()
    return jsonify(Resp(Resp.SUCCESS))


@bp_api.route("/vuln", methods=['GET', 'PUT'])
@login_check
def vuln_list():
    if request.method == 'GET':
        return jsonify(Resp(Resp.SUCCESS, to_json(vuln_record.objects())))
    data = request.get_json()
    if not data:
        raise ApiException("Incorrect format!")
    v = vuln_record(pathid=data.get('pathid'),
                    scenario=data.get('scenario'),
                    severity=data.get('severity'),
                    status=data.get('status') or "open",
                    result=data.get('result'),
                    evidence=data.get('evidence') or {})
    v.save()
    return jsonify(Resp(Resp.SUCCESS, to_json(v)))


@bp_api.route("/vuln/<_id>", methods=['PUT', 'DELETE'])
@login_check
def vuln_update(_id):
    if request.method == 'DELETE':
        vuln_record.objects(id=_id).delete()
        return jsonify(Resp(Resp.SUCCESS))
    data = request.get_json()
    if not data:
        raise ApiException("Incorrect format!")
    obj = vuln_record.objects(id=_id).first()
    if not obj:
        raise ApiException("vuln not found")
    for key in ["severity", "status", "result", "evidence"]:
        if key in data:
            setattr(obj, key, data[key])
    obj.save()
    return jsonify(Resp(Resp.SUCCESS))


@bp_api.route("/testcase", methods=['GET', 'PUT'])
@login_check
def testcase_list():
    if request.method == 'GET':
        return jsonify(Resp(Resp.SUCCESS, to_json(test_case.objects())))
    data = request.get_json()
    if not data:
        raise ApiException("Incorrect format!")
    t = test_case(name=data.get('name'),
                  pathid=data.get('pathid'),
                  method=data.get('method'),
                  url=data.get('url'),
                  headers=data.get('headers') or {},
                  body=data.get('body'),
                  expected=data.get('expected') or {})
    t.save()
    return jsonify(Resp(Resp.SUCCESS, to_json(t)))


@bp_api.route("/testcase/<_id>", methods=['PUT', 'DELETE'])
@login_check
def testcase_update(_id):
    if request.method == 'DELETE':
        test_case.objects(id=_id).delete()
        return jsonify(Resp(Resp.SUCCESS))
    data = request.get_json()
    if not data:
        raise ApiException("Incorrect format!")
    obj = test_case.objects(id=_id).first()
    if not obj:
        raise ApiException("testcase not found")
    for key in ["name", "method", "url", "headers", "body", "expected"]:
        if key in data:
            setattr(obj, key, data[key])
    obj.save()
    return jsonify(Resp(Resp.SUCCESS))


# --------------------------- ↓ 角色/账号 ↓------------------------------------
@bp_api.route("/sso/account", methods=['GET', 'PUT'])
@policy_check(PolicyEnum.MANAGE, method='PUT')
def sso_account():
    """
    GET: 获取账号列表
    PUT: 添加账号
    :return:
    """
    if request.method == 'GET':
        accounts = SsoAccount.objects.exclude('password')
        return jsonify(Resp(Resp.SUCCESS, to_json(accounts)))

    if request.method == 'PUT':
        data = request.get_json()
        if not data:
            raise ApiException("Incorrect format!")
        try:
            sso_account_record(username=data.get('username'), password=data.get('password'),
                               describe=data.get('describe'))
        except Exception as e:
            raise ApiException(e)

    return jsonify(Resp(Resp.SUCCESS))


@bp_api.route("/sso/account/<_id>", methods=['GET', 'PUT', 'DELETE'])
@policy_check(PolicyEnum.MANAGE)
def sso_account_op(_id):
    """
    GET: 获取该账号明细
    PUT: 修改账号信息
    DELETE: 删除
    :param _id:
    :return:
    """
    if request.method == 'GET':
        account = SsoAccount.objects(id=_id)
        if len(account) == 0:
            raise ApiException("id error!")
        account = account[0]
        return jsonify(Resp(Resp.SUCCESS, to_json(account)))

    if request.method == 'DELETE':
        SsoAccount.objects(id=_id).delete()
        return jsonify(Resp(Resp.SUCCESS))

    if request.method == 'PUT':
        data = request.get_json()
        if not data:
            raise ApiException("Incorrect format!")
        username = data.get('username')
        pwd = data.get('password')
        desc = data.get('describe')

        if not username:
            return jsonify(Resp(Resp.ERROR, '请输入用户名'))
        sso_account_record(username, pwd, desc, _id)
        return jsonify(Resp(Resp.SUCCESS))


@bp_api.route("/<_id>/refresh", methods=['DELETE'])
@login_check
def auth_refresh(_id):
    """
    刷新自己工作空间的认证信息
    :param _id: (对应工作空间id）
    :return:
    """
    refresh_session(session.get('username'), _id)
    return jsonify(Resp(Resp.SUCCESS))
