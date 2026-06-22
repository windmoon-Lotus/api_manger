import redis
from apiAnalysis.conf.conf import *
redis_pool = redis.ConnectionPool(host=redis_host, port=redis_port, db=redis_db, password=redis_password)