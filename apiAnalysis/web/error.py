from . import bp_api, bp_web
from ..model.model import Resp
from ..model.exception import ApiException
from flask import jsonify, current_app, session
from ..conf.conf import logger


@bp_api.errorhandler(ApiException)
def api_exception(e):
    """
    api异常
    :param e:
    :return:
    """
    logger.error("{} except: {}".format(session.get('username'), e), exc_info=True)
    return jsonify(Resp(Resp.ERROR, str(e)))


@bp_api.errorhandler(AssertionError)
def api_assert(e):
    """
    断言异常
    :param e:
    :return:
    """
    logger.error("{} except: {}".format(session.get('username'), e), exc_info=True)
    return jsonify(Resp(Resp.ERROR, "断言异常！{}".format(str(e))))


@bp_api.errorhandler(Exception)
def exception(e):
    """
    api异常
    :param e:
    :return:
    """
    logger.error("{} except: {}".format(session.get('username'), e), exc_info=True)
    return jsonify(Resp(Resp.ERROR, str(e)))


@bp_web.errorhandler(Exception)
def web_exception(e):
    """
    web全局异常
    :param e:
    :return:
    """
    logger.error("{} except: {}".format(session.get('username'), e), exc_info=True)
    return jsonify(Resp(Resp.ERROR, str(e)))


@bp_web.errorhandler(AssertionError)
def web_assert(e):
    """
    断言异常
    :param e:
    :return:
    """
    logger.error("{} assert error!".format(session.get('username')), exc_info=True)
    return jsonify(Resp(Resp.ERROR, "断言异常！{}".format(str(e))))

