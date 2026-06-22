import hashlib

import redis
from apscheduler.schedulers.blocking import BlockingScheduler
from apiAnalysis.common.func import *
from apiAnalysis.common.domain_root import *
from apiAnalysis.conf.conf import logger
from apiAnalysis.model.model import PolicyEnum, HeaderModel, BodyModel
from apiAnalysis.db.collection import Workspace
from apiAnalysis.conf.secret import *
from apiAnalysis.common.i18n import t, get_lang
from apiAnalysis.runtime_check import format_checks, run_checks
app_path = os.path.dirname(os.path.realpath(__file__))

redis_pool = redis.ConnectionPool(host=redis_host, port=redis_port, db=redis_db, password=redis_password)

# 简单初始化两个账号，实际使用时可自行接入公司内部sso
users = {
    'admin': {
        'password': 'admin123',
        'role': [PolicyEnum.MANAGE.value, PolicyEnum.ACCESS.value]
    },
    'normal': {
        'password': 'normal123',
        'role': [PolicyEnum.ACCESS.value]
    }
}


def init():
    from threading import Thread
    from apiAnalysis.core.jobs import status_clear

    # 定时任务
    scheduler = BlockingScheduler()
    scheduler.add_job(status_clear, 'cron', hour=0)
    Thread(target=scheduler.start, daemon=True).start()

    # mongo
    from mongoengine import connect
    connect(
        mongo_database,
        username=mongo_user,
        password=mongo_password,
        host=mongo_host,
        port=mongo_port,
        connect=False
    )
from apiAnalysis.core.lib import deal_scan, dictt, get_roles

def scan():
    from pymongo import MongoClient

    if mongo_password == "":
        client = MongoClient(mongo_host, mongo_port)
    else:
        client = MongoClient('mongodb://%s:%s@%s:%s' % (mongo_user, mongo_password, mongo_host, mongo_port))
    db = client[mongo_database]
    data = db["response"]
    # data=db["packet_data"]
    rows = data.find()
    #print(134)
    for row in rows:

        #print(get_domain_root(row["request"]["url"]))
        if get_domain_root(row["request"]["url"]) == "example.com":
            for ws in Workspace.objects(depart_name="example", system_name="all", status=Workspace.STATUS_START,
                                            cname="admin"):
                assert isinstance(ws, Workspace)
                #print(3214565)
                rs = redis.Redis(connection_pool=redis_pool)
                # 去掉完全一样的请求
                endata=str(row["request"]["url"])+str(row["request"]["method"])
                digest = hashlib.md5(str(endata).encode('utf-8')).digest()
                heap = rs.hget("parse_heap:{}:{}".format(ws.cname, str(ws.id)), digest)
                #if heap:
                #    logger.debug("filter the same request: {}".format(row["request"]["url"]))
                #    continue
                #rs.hset("parse_heap:{}:{}".format(ws.cname, str(ws.id)), digest, row["request"]["url"])
                try:

                    heads = row["request"]["headers"]
                    # print(row["_id"])
                    head = dictt(heads)
                    if row["request"]["method"] not in [HeaderModel.METHOD_GET, HeaderModel.METHOD_POST,
                                                        HeaderModel.METHOD_DELETE,
                                                        HeaderModel.METHOD_PUT]:
                        logger.error("暂不支持的方法：{}".format(row["request"]["method"]))
                        continue
                    if "postData" in row["request"]:
                        header = HeaderModel(url=row["request"]["url"], method=row["request"]["method"], header=head)
                        body = BodyModel(row["request"]["postData"]["text"], charset='utf-8')
                        deal_scan("test", header, body, ws, get_roles(ws))
                        logger.debug("scan post body parsed for url=%s", row["request"]["url"])
                    else:
                        header = HeaderModel(url=row["request"]["url"], method=row["request"]["method"], header=head)
                        body = BodyModel()
                        deal_scan("test", header, body, ws, get_roles(ws))
                        logger.debug("scan request parsed for url=%s", row["request"]["url"])


                except Exception as e:
                    logger.exception(e)
        else:
            #print(123)
            heads = row["request"]["headers"]
            # print(row["_id"])
            head = dictt(heads)
            host = head["Host"]
            #print(host)
            for ws in Workspace.objects(hosts=host, status=Workspace.STATUS_START,
                                        depart_name="example"):
                assert isinstance(ws, Workspace)
                logger.debug("scan workspace matched: %s", ws.id)
                rs = redis.Redis(connection_pool=redis_pool)
                # 去掉完全一样的请求
                endata = str(row["request"]["url"]) + str(row["request"]["method"])
                digest = hashlib.md5(str(endata).encode('utf-8')).digest()
                heap = rs.hget("parse_heap:{}:{}".format(ws.cname, str(ws.id)), digest)
                if heap:
                    logger.debug("filter the same request: {}".format(row["request"]["url"]))
                    continue
                rs.hset("parse_heap:{}:{}".format(ws.cname, str(ws.id)), digest, row["request"]["url"])
                try:
                    if row["request"]["method"] not in [HeaderModel.METHOD_GET, HeaderModel.METHOD_POST,
                                                        HeaderModel.METHOD_DELETE,
                                                        HeaderModel.METHOD_PUT]:
                        logger.error("暂不支持的方法：{}".format(row["request"]["method"]))
                        continue
                    if "postData" in row["request"]:
                        header = HeaderModel(url=row["request"]["url"], method=row["request"]["method"],
                                             header=head)
                        body = BodyModel(row["request"]["postData"]["text"], charset='utf-8')
                        deal_scan("test", header, body, ws, get_roles(ws))
                        logger.debug("scan post body parsed for url=%s", row["request"]["url"])
                    else:
                        header = HeaderModel(url=row["request"]["url"], method=row["request"]["method"],
                                             header=head)
                        body = BodyModel()
                        deal_scan("test", header, body, ws, get_roles(ws))
                        logger.debug("scan request parsed for url=%s", row["request"]["url"])

                except Exception as e:
                    logger.exception(e)


def create_app():
    from flask import Flask
    from flask_cors import CORS
    from .web import bp_api, bp_web, bp_ws
    from .core.lib import ScanThread
    from .conf.conf import cors_origin

    checks = run_checks(include_tools=False)
    logger.info("startup checks:\n%s", format_checks(checks))

    init()

    app = Flask(__name__)
    app.secret_key = secret_key

    CORS(bp_api, supports_credentials=True, origins=cors_origin)
    CORS(bp_ws, supports_credentials=True, origins=cors_origin)

    app.register_blueprint(bp_api)
    app.register_blueprint(bp_web)
    app.register_blueprint(bp_ws)

    # jinja2 function
    app.add_template_global(system_types, 'system_types')
    app.add_template_global(workspace_status, 'workspace_status')
    app.add_template_global(func_account, 'func_account')
    app.add_template_global(is_manager, 'is_manager')
    app.add_template_global(time_now, 'time_now')
    app.add_template_global(t, 't')
    app.add_template_global(get_lang, 'get_lang')

    app.add_template_filter(time_show, 'time_show')
    app.add_template_filter(ws_roles, 'ws_roles')
    app.add_template_filter(format_json, 'json_show')
    app.add_template_filter(format_request, 'request_show')
    app.add_template_filter(format_response, 'response_show')
    app.add_template_filter(str_show, 'str_show')
    app.add_template_filter(request_num, 'request_num')

    # 开启扫描任务
    ScanThread().start()

    return app
