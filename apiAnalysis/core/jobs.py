from apiAnalysis.conf.conf import logger
from apiAnalysis.db.collection import Workspace


def status_clear():
    """
    刷新状态
    :return:
    """
    logger.info("job status_clear ...")
    # 工作空间状态
    Workspace.objects(Workspace.status == Workspace.STATUS_START).update(status=Workspace.STATUS_STOP)


__all__ = [
    'status_clear'
]
