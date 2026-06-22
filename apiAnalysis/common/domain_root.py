import re
from urllib import parse
import logging

topRootDomain = (
    '.com', '.la', '.cn', '.io', '.co', '.info', '.net', '.org', '.me', '.mobi',
    '.us', '.biz', '.xxx', '.ca', '.co.jp', '.com.cn', '.net.cn',
    '.org.cn', '.mx', '.tv', '.ws', '.ag', '.com.ag', '.net.ag',
    '.org.ag', '.am', '.asia', '.at', '.be', '.com.br', '.net.br',
    '.bz', '.com.bz', '.net.bz', '.cc', '.com.co', '.net.co',
    '.nom.co', '.de', '.es', '.com.es', '.nom.es', '.org.es',
    '.eu', '.fm', '.fr', '.gs', '.in', '.co.in', '.firm.in', '.gen.in',
    '.ind.in', '.net.in', '.org.in', '.it', '.jobs', '.jp', '.ms',
    '.com.mx', '.nl', '.nu', '.co.nz', '.net.nz', '.org.nz',
    '.se', '.tc', '.tk', '.tw', '.com.tw', '.idv.tw', '.org.tw',
    '.hk', '.co.uk', '.me.uk', '.org.uk', '.vg', ".com.hk")
logger = logging.getLogger(__name__)


def get_domain_root(url):
    '''获取根域名。'''
    domain_root = ""
    try:
        # 若不是 http或https开头，则补上方便正则匹配规则
        if len(url.split("://")) <= 1 and url[0:4] != "http" and url[0:5] != "https":
            url = "http://" + url

        reg = r'[^\.]+(' + '|'.join([h.replace('.', r'\.')
                                     for h in topRootDomain]) + ')$'
        pattern = re.compile(reg, re.IGNORECASE)

        parts = parse.urlparse(url)
        host = parts.netloc
        m = pattern.search(host)
        res = m.group() if m else host
        domain_root = "" if not res else res
    except Exception as ex:
        logger.debug("get_domain_root error: %s", ex)
    return domain_root
