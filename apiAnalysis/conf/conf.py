import re
import os

replacements = [
    (re.compile(r'\b\d+\b'), '[NUMBER]'),
    # 可替换 "固定字符串" 为 "对应值"，以test为例
    (re.compile(r'\btest\b'), '[name]'),
]
import logging
from apiAnalysis.conf.secret import *

_log_level_name = os.getenv("API_MANAGER_LOG_LEVEL", "INFO").upper()
_log_level = getattr(logging, _log_level_name, logging.INFO)
logging.basicConfig(level=_log_level, format="%(asctime)s - %(levelname)s %(filename)s %(funcName)s - %(message)s")
logger = logging.getLogger(__name__)

# 代理
proxies = {
    "http": None,
    "https": None
}
# proxies = {
#   "http": "http://127.0.0.1:8080",
#   "https": "https://127.0.0.1:8080",
# }

# CORS is local-only by default. Use a comma-separated allowlist when the UI is
# intentionally served from other trusted origins.
_cors_value = os.getenv("API_MANAGER_CORS_ORIGINS", "http://127.0.0.1:5000,http://localhost:5000")
cors_origin = [item.strip() for item in _cors_value.split(",") if item.strip()]

# requests超时时间
timeout = 5
account = ""
cname = ""
#error 信息
error = []
# auth_session有效时间（分钟）
session_timeout = 5
# 页面监听有效时间（分钟）
listening_timeout = 1
# 数据统计间隔时间（分钟）
statistics_timeout = 3

# AI evaluation endpoint (optional)
ai_endpoint = os.getenv("API_MANAGER_AI_ENDPOINT") or None
ai_api_key = os.getenv("API_MANAGER_AI_API_KEY") or None
try:
    ai_timeout = int(os.getenv("API_MANAGER_AI_TIMEOUT", "10"))
except ValueError:
    ai_timeout = 10

# External tool paths (optional; used by future adapters and doctor checks)
sqlmap_path = os.getenv("SQLMAP_PATH")
nuclei_path = os.getenv("NUCLEI_PATH")
zap_path = os.getenv("ZAP_PATH")
schemathesis_path = os.getenv("SCHEMATHESIS_PATH")
ffuf_path = os.getenv("FFUF_PATH")

# 全局编码
encoding = 'utf-8'

# 扫码任务线程数量
max_workers = 20

# pattern
space_pattern = re.compile(r"\s+")

# 过滤
scope_exclude = r'\.gif$|\.jpg$|\.png$|\.css$|\.js$|\.ico$|\.ttf$|\.woff2$|\.woff$'
scope_exclude += r'|\.gif\?|\.jpg\?|\.png\?|\.css\?|\.js\?|\.ico\?|\.ttf\?|\.woff2\?|\.woff\?'
scope_exclude = re.compile(scope_exclude)
