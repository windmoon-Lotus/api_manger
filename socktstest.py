import socket
import ssl

def send_http_request(sock, request):
    """发送原始HTTP请求并返回响应"""
    sock.sendall(request.encode())
    response = b''
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
        # 简单判断HTTP头是否接收完成
        if b'\r\n\r\n' in response:
            break
    return response

# 代理服务器配置
proxy_host = '127.0.0.1'
proxy_port = 8888

# 目标服务器配置
target_host = 'relay.example.com'
target_port = 443

# 创建原始socket连接
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((proxy_host, proxy_port))

# 构造CONNECT请求
connect_request = (
    f"CONNECT {target_host}:{target_port} HTTP/1.0\r\n"
    f"Host: {target_host}:{target_port}\r\n"
    "Connection: keep-alive\r\n"  # 强制保持连接
    "\r\n"
)

# 发送请求并获取响应
response = send_http_request(sock, connect_request)
print("CONNECT Response:", response.decode())

# 检查响应状态码
if b"200" not in response.splitlines()[0]:
    raise Exception("CONNECT failed")

# 如果目标是HTTPS，需要SSL包装（可选）
sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLS)

# 在此连接上发送后续请求示例
http_request = (
    f"POST multiplex\r\n"
    f"Host: {target_host}\r\n"
    "\r\n"  # 最后一个请求后关闭连接
    "\r\n"
)

response = send_http_request(sock, http_request)
print("HTTP Response:", response.decode())

# 根据响应内容执行不同操作
if b"200 OK" in response:
    print("Request successful")
elif b"404" in response:
    print("Page not found")
else:
    print("Unexpected response")

sock.close()