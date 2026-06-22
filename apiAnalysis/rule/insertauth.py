import requests
import json
from typing import Dict, List, Optional


class AdvancedPrivilegeScanner:
    def __init__(self, config: Dict):
        """
        :param config: 包含测试环境和接口定义的配置字典
        """
        self.users = config['test_users']  # 不同权限用户凭证
        self.interfaces = config['interfaces']  # 待检测接口列表
        self.env = config['environment']  # 测试环境配置
        # 接口关系映射 (示例格式)
        self.interface_relations = {
            'create_user': {'read_endpoint': '/api/users/{id}'},
            'delete_order': {'verify_endpoint': '/api/orders/{id}'}
        }

    def run_full_scan(self):
        """执行完整扫描流程"""
        results = {}
        for interface in self.interfaces:
            print(f"正在扫描接口: {interface['name']}")
            result = self.test_interface(interface)
            results[interface['name']] = result
        return results

    def test_interface(self, interface: Dict) -> Dict:
        """测试单个接口"""
        # 初始化测试结果
        result = {
            'path': interface['path'],
            'vertical': '安全',
            'horizontal': '安全',
            'evidence': [],
            'test_cases': []
        }

        # 获取接口元数据
        #required_auth = interface.get('auth_required', False)
        operation_type = interface['type']  # CREATE/READ/UPDATE/DELETE
        params = interface['params']
        query_params = interface['query_params']
        if operation_type == "query_api" and len(params) < 1 and len(query_params) < 1:
            return result
        result['vertical'] = self.test_vertical_escalation(interface)
        result['horizontal'] = self.test_horizontal_escalation(interface)
        return result

    def test_vertical_escalation(self, interface: Dict) -> str:
        """垂直越权测试逻辑"""
        # 使用低权限用户执行高危操作
        low_priv_user = self.users['low_priv']
        if low_priv_user:
            return "无需测试"
        response = self.execute_request(interface, low_priv_user)

        # 初步状态码检测
        if response.status_code in [200, 201, 204]:
            # 动态验证操作是否实际生效
            if self.verify_operation_effect(interface, low_priv_user):
                return "存在垂直越权漏洞"

        # 详细错误信息分析
        elif response.status_code == 403:
            return "安全 (权限校验正常)"

        return "需人工验证"

    def test_horizontal_escalation(self, interface: Dict) -> str:
        """水平越权测试逻辑"""
        # 使用用户A访问用户B的资源
        user_o = self.users['user_a']
        user_m = self.users['user_b']
        response = self.execute_request(
            interface,
            user_m
        )
        response_m = self.execute_request(
            interface,
            user_m
        )
        # 分析响应内容
        if response.status_code == 200:
            if self.check_data(response.json(), response_m.json()):
                return "安全 (权限校验正常)"
            return "存在水平越权漏洞"

        return "安全"

    def verify_operation_effect(self, interface: Dict, user: Dict) -> bool:
        """验证高危操作实际效果"""
        # 根据接口关系获取验证端点
        relation = self.interface_relations.get(interface['name'], {})
        if verify_endpoint := relation.get('verify_endpoint'):
            # 构造验证请求
            verify_response = self.execute_verify_request(
                verify_endpoint,
                user
            )
            return verify_response.status_code == 200

        # 默认根据接口类型判断
        return False if interface['type'] in ['DELETE', 'UPDATE'] else True


    def check_data_ownership(self, data: Dict, data2: Dict) -> bool:
        """检查数据所有权（示例实现）"""
        # 根据实际业务逻辑实现，例如：
        pass

    def replace_owner_ids(self, params: Dict, target_user: Dict) -> Dict:
        """替换参数中的用户标识符（支持嵌套结构解析）"""
        param_str = json.dumps(params)
        param_str = param_str.replace('${target_user}', target_user['id'])
        return json.loads(param_str)


# 示例配置文件
CONFIG = {
    "test_users": {
        "admin": {"id": "admin_01", "token": "admin_token"},
        "low_priv": {"id": "user_01", "token": "user_token"},
        "user_a": {"id": "user_02", "token": "user_token_2"},
        "user_b": {"id": "user_03", "token": "user_token_3"}
    },
    "interfaces": [
        {
            "name": "delete_user",
            "type": "DELETE",
            "path": "/api/users/{userId}",
            "method": "DELETE",
            "auth_params": [
                {"in": "header", "name": "Authorization", "key": "token"}
            ],
            "params": {"userId": "${target_user}"}
        },
        {
            "name": "get_user_orders",
            "type": "READ",
            "path": "/api/users/{userId}/orders",
            "method": "GET",
            "auth_params": [
                {"in": "header", "name": "Authorization", "key": "token"}
            ]
        }
    ],
    "environment": {
        "base_url": "http://test-api.example.com",
        "test_data": {"test_order_id": "ORD_001"}
    }
}

if __name__ == "__main__":
    scanner = AdvancedPrivilegeScanner(CONFIG)
    results = scanner.run_full_scan()

    print("扫描结果：")
    print(json.dumps(results, indent=2, ensure_ascii=False))