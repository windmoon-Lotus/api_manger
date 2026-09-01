from flask import session, redirect, url_for
from . import bp_web
from ..common.decorators import *
from ..model.exception import *
from ..model.model import PolicyEnum
from ..db.collection import *


@bp_web.route("/login")
@templated("/login.html")
def login():
    pass


@bp_web.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("web.login"))


@bp_web.route("/account")
@login_check
@templated("/sso-account.html")
def sso_account():
    return {'hits': SsoAccount.objects()}


@bp_web.route("/account-add")
@policy_check(PolicyEnum.MANAGE)
@templated("/sso-account-edit.html")
def sso_account_add():
    return {'account': {}}


@bp_web.route("/account/edit/<_id>")
@policy_check(PolicyEnum.MANAGE)
@templated("/sso-account-edit.html")
def sso_account_edit(_id):
    account = SsoAccount.objects(id=_id)
    if len(account) == 0:
        raise ApiException("account {} not found!".format(_id))
    account = account[0]
    return {
        'account': account
    }


@bp_web.route("/account/show/<_id>")
@policy_check(PolicyEnum.MANAGE)
@templated("/sso-account-show.html")
def sso_account_show(_id):
    account = SsoAccount.objects(id=_id)
    if len(account) == 0:
        raise ApiException("account {} not found!".format(_id))
    account = account[0]
    return {
        'account': account
    }
