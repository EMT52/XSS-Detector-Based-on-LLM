"""
LLM HTTP 请求构造与执行模块。

负责输入接口识别、参数结构适配，以及 HTTP 请求用例的构造与执行。
"""

import re
import requests
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)


class LLMRequestMixin:
    def _extract_array_params(self, php_code: str) -> List[Dict]:
        """
        识别PHP关联数组参数
        例如: $row = $_GET['temp_kNxtes']; echo $row["title"];
        返回: [{'param': 'temp_kNxtes', 'key': 'title', 'method': 'GET'}]
        """
        array_params = []
        seen = set()  # 用于去重
        
        # 模式1: 直接从超全局变量获取数组，然后访问其键
        # 例如: $row = $_GET['param']; echo $row["key"];
        patterns = [
            # $_GET['param'] 赋值给变量，然后访问数组键
            (r'\$(\w+)\s*=\s*.*?\$_(GET|POST|REQUEST|COOKIE)\[[\'"](\w+)[\'"]\].*?;\s*.*?\$\1\[[\'"](\w+)[\'"]\]', 'array_assign'),
            # isset($_GET['param']) ? $_GET['param'] : array(...) 然后访问键
            (r'\$(\w+)\s*=\s*isset\(\$_(GET|POST|REQUEST|COOKIE)\[[\'"](\w+)[\'"]\]\).*?;\s*.*?\$\1\[[\'"](\w+)[\'"]\]', 'array_isset'),
        ]
        
        for pattern, pattern_type in patterns:
            matches = re.finditer(pattern, php_code, re.DOTALL)
            for match in matches:
                if pattern_type == 'array_assign':
                    var_name, method, param_name, array_key = match.groups()
                elif pattern_type == 'array_isset':
                    var_name, method, param_name, array_key = match.groups()
                
                # 使用元组作为唯一标识进行去重
                unique_key = (param_name, array_key, method)
                if unique_key not in seen:
                    seen.add(unique_key)
                    array_params.append({
                        'param': param_name,
                        'key': array_key,
                        'method': method,
                        'var_name': var_name
                    })
                    logger.info(f"[LLM Static] Detected array param: {param_name}[{array_key}] from ${method}")
        
        return array_params

    

    def _prepare_payload_requests(
        self,
        test_put_path: str,
        payload: str,
        analysis: Dict = None,
    ) -> Dict:
        """按原有规则和顺序构造 Payload 的请求用例。"""
        from .helper_model import extract_main_param
        import re
        
        # 构建测试URL
        uri = f"{test_put_path.split('/')[-3]}/{test_put_path.split('/')[-2]}/{test_put_path.split('/')[-1]}"
        url = f"http://localhost/{uri}"
        
        # 优先使用静态分析的参数名，否则使用 extract_main_param
        if analysis and analysis.get('input_params'):
            main_param = analysis['input_params'][0]['name']
            logger.info(f"[LLM Static] Using param from static analysis: {main_param}")
        else:
            main_param = extract_main_param(test_put_path)
            logger.info(f"[LLM Static] Using param from extract_main_param: {main_param}")
        # 读取PHP代码，分析参数类型、数组函数和安全编码函数
        try:
            with open(test_put_path, 'r', encoding='utf-8', errors='ignore') as f:
                php_code = f.read()
            uses_array_functions = bool(re.search(r'\b(implode|join|array_map|array_filter|in_array)\s*\(', php_code))
            
            # 检查是否使用了安全的编码函数
            safe_encoding_functions = [
                r'json_encode\s*\(',           # JSON编码（会转义HTML特殊字符）
                r'htmlspecialchars\s*\(',      # HTML实体编码
                r'htmlentities\s*\(',          # HTML实体编码
                r'addslashes\s*\(',            # 转义引号
                r'mysqli_real_escape_string\s*\(',  # MySQL转义
                r'pg_escape_string\s*\(',      # PostgreSQL转义
                r'urlencode\s*\(',             # URL编码
                r'rawurlencode\s*\(',          # URL编码
                r'base64_encode\s*\(',         # Base64编码
            ]
            
            uses_safe_encoding = any(re.search(pattern, php_code, re.IGNORECASE) for pattern in safe_encoding_functions)
            
            if uses_safe_encoding:
                logger.info(f"[LLM Static] Detected safe encoding function in code")
                # 检查具体使用了哪些编码函数
                for pattern in safe_encoding_functions:
                    if re.search(pattern, php_code, re.IGNORECASE):
                        func_name = pattern.split(r'\s*\(')[0].replace('\\', '')
                        logger.info(f"[LLM Static] Found encoding function: {func_name}")
            
            # 提取所有GET、POST、COOKIE参数
            all_get_params = re.findall(r'\$_GET\[[\"\'](\w+)[\"\']\]', php_code)
            all_post_params = re.findall(r'\$_POST\[[\"\'](\w+)[\"\']\]', php_code)
            all_request_params = re.findall(r'\$_REQUEST\[[\"\'](\w+)[\"\']\]', php_code)
            all_cookie_params = re.findall(r'\$_COOKIE\[[\"\'](\w+)[\"\']\]', php_code)
            
            all_get_params = list(set(all_get_params))  # 去重
            all_post_params = list(set(all_post_params))
            all_request_params = list(set(all_request_params))
            all_cookie_params = list(set(all_cookie_params))
            
            # 识别PHP关联数组参数（如 $row["title"] 来自 $_GET['temp_kNxtes']）
            array_params = self._extract_array_params(php_code)
            logger.info(f"[LLM Static] Found array params: {array_params}")
            
            logger.debug(f"[LLM Static] Found GET params: {all_get_params}")
            logger.debug(f"[LLM Static] Found POST params: {all_post_params}")
            logger.debug(f"[LLM Static] Found REQUEST params: {all_request_params}")
            logger.debug(f"[LLM Static] Found COOKIE params: {all_cookie_params}")
        except:
            uses_array_functions = False
            all_get_params = [main_param]
            all_post_params = []
            all_request_params = []
            all_cookie_params = []
            array_params = []
        
        # 确定主参数的请求方法
        param_method = None
        if main_param in all_cookie_params:
            param_method = 'COOKIE'
        elif main_param in all_post_params:
            param_method = 'POST'
        elif main_param in all_get_params:
            param_method = 'GET'
        elif main_param in all_request_params:
            param_method = 'BOTH'  # REQUEST可以接受GET或POST
        
        # 构建测试用例
        test_cases = []
        
        # 如果是COOKIE参数，尝试Cookie请求
        if param_method == 'COOKIE':
            # Cookie请求 - 格式1: 单个Cookie
            test_cases.append({
                'method': 'COOKIE',
                'url': url,
                'cookies': {main_param: payload},
                'data': None
            })
            
            # Cookie请求 - 格式2: 带其他Cookie参数
            if len(all_cookie_params) > 1:
                cookies = {main_param: payload}
                for param in all_cookie_params:
                    if param != main_param:
                        cookies[param] = '1'
                test_cases.append({
                    'method': 'COOKIE',
                    'url': url,
                    'cookies': cookies,
                    'data': None
                })
        
        # 如果是POST参数或REQUEST参数，尝试POST请求
        if param_method in ['POST', 'BOTH', None]:
            # POST请求 - 格式1: 单个参数
            test_cases.append({
                'method': 'POST',
                'url': url,
                'data': {main_param: payload}
            })
            
            # POST请求 - 格式2: 带其他POST参数（只有多个参数时才添加）
            if len(all_post_params) > 1:
                post_data = {main_param: payload}
                for param in all_post_params:
                    if param != main_param:
                        post_data[param] = '1'
                test_cases.append({
                    'method': 'POST',
                    'url': url,
                    'data': post_data
                })
            
            # POST请求 - 格式3: 数组格式（如果检测到数组函数）
            if uses_array_functions:
                test_cases.append({
                    'method': 'POST',
                    'url': url,
                    'data': {f'{main_param}[]': [payload, 'test']}
                })
        
        # 如果是GET参数或REQUEST参数，尝试GET请求
        if param_method in ['GET', 'BOTH', None]:
            # GET请求 - 格式1: 单个参数
            params_str = f"{main_param}={payload}"
            test_cases.append({
                'method': 'GET',
                'url': f"{url}?{params_str}",
                'data': None
            })
            
            # GET请求 - 格式2: 带其他GET参数（只有多个参数时才添加）
            if len(all_get_params) > 1:
                params_str = f"{main_param}={payload}"
                for param in all_get_params:
                    if param != main_param:
                        params_str += f"&{param}=1"
                test_cases.append({
                    'method': 'GET',
                    'url': f"{url}?{params_str}",
                    'data': None
                })
            
            # GET请求 - 格式3: 数组格式
            if uses_array_functions:
                # 检测赋值覆盖模式: $_GET["file"] = $_GET['input']
                # 此时数组必须挂在源头参数上（否则 $_GET["file"] 会被 input 覆盖成 null/字符串）
                assign_match = re.search(
                    r'\$_GET\[[\"\'](\w+)[\"\']\]\s*=\s*\$_GET\[[\"\'](\w+)[\"\']\]',
                    php_code
                )
                if assign_match:
                    assign_target, assign_source = assign_match.groups()
                    array_param = assign_source
                    logger.info(
                        f"[LLM Static] Assign-override: $_GET[{assign_target}] = $_GET[{assign_source}], "
                        f"array format on source param '{assign_source}'"
                    )
                else:
                    array_param = main_param
                params_str = f"{array_param}[]={payload}&{array_param}[]=test"
                test_cases.append({
                    'method': 'GET',
                    'url': f"{url}?{params_str}",
                    'data': None
                })
        
        # 添加关联数组参数测试（针对 bWAPP 文件夹1 这种情况）
        if array_params:
            for array_param in array_params:
                param_name = array_param['param']
                array_key = array_param['key']
                method = array_param['method']
                
                if method in ['GET', 'REQUEST']:
                    # 格式: param[key]=payload
                    params_str = f"{param_name}[{array_key}]={payload}"
                    test_cases.append({
                        'method': 'GET',
                        'url': f"{url}?{params_str}",
                        'data': None
                    })
                    logger.info(f"[LLM Static] Added array param test: {param_name}[{array_key}]")
                    
                    # 如果有其他参数，也一起测试
                    if len(all_get_params) > 1:
                        params_str = f"{param_name}[{array_key}]={payload}"
                        for param in all_get_params:
                            if param != param_name:
                                params_str += f"&{param}=1"
                        test_cases.append({
                            'method': 'GET',
                            'url': f"{url}?{params_str}",
                            'data': None
                        })
                
                elif method == 'POST':
                    # POST 数组参数
                    post_data = {f"{param_name}[{array_key}]": payload}
                    test_cases.append({
                        'method': 'POST',
                        'url': url,
                        'data': post_data
                    })
                    logger.info(f"[LLM Static] Added POST array param test: {param_name}[{array_key}]")
        
        # 添加参数组合测试（针对条件输出场景，如 bWAPP 文件夹7）
        # 场景：输出在 if 条件块内，需要同时传递漏洞参数和触发参数
        
        # 合并所有可能的 GET 参数（包括 $_GET 和 $_REQUEST）
        all_possible_get_params = list(set(all_get_params + all_request_params))
        
        if len(all_possible_get_params) > 1:
            logger.info(f"[LLM Static] Adding parameter combination tests for conditional output")
            logger.info(f"[LLM Static] Testing {len(all_possible_get_params)} parameters: {all_possible_get_params}")
            
            # 对每个参数作为潜在的漏洞参数
            for vuln_param in all_possible_get_params:
                if vuln_param == main_param:
                    continue  # 主参数已经测试过
                
                # 与其他参数组合（其他参数作为触发条件）
                for trigger_param in all_possible_get_params:
                    if trigger_param != vuln_param:
                        params_str = f"{vuln_param}={payload}&{trigger_param}=1"
                        test_cases.append({
                            'method': 'GET',
                            'url': f"{url}?{params_str}",
                            'data': None
                        })
                        logger.debug(f"[LLM Static] Added combo: {vuln_param}={payload[:20]}..., {trigger_param}=1")
        
        # 对 POST 参数也做类似处理
        all_possible_post_params = list(set(all_post_params + all_request_params))
        
        if len(all_possible_post_params) > 1:
            logger.info(f"[LLM Static] Adding POST parameter combination tests")
            
            for vuln_param in all_possible_post_params:
                if vuln_param == main_param:
                    continue
                
                for trigger_param in all_possible_post_params:
                    if trigger_param != vuln_param:
                        post_data = {vuln_param: payload, trigger_param: '1'}
                        test_cases.append({
                            'method': 'POST',
                            'url': url,
                            'data': post_data
                        })
                        logger.debug(f"[LLM Static] Added POST combo: {vuln_param}, {trigger_param}=1")
        
        # 移除原来的 REQUEST 参数单独处理（已经合并到上面）
        return {
            "url": url,
            "main_param": main_param,
            "php_code": locals().get("php_code", ""),
            "uses_safe_encoding": locals().get("uses_safe_encoding"),
            "test_cases": test_cases,
        }

    def _execute_request_case(self, test_case: Dict, index: int, total: int):
        """执行一个请求用例并返回原始响应，不参与漏洞判定。"""
        if test_case['method'] == 'COOKIE':
            logger.info(f"[LLM Static] Testing COOKIE request {index}/{total}")
            logger.info(f"[LLM Static] COOKIE URL: {test_case['url']}")
            logger.info(f"[LLM Static] COOKIE data: {test_case['cookies']}")
            return requests.get(test_case['url'], cookies=test_case['cookies'], timeout=10)
        if test_case['method'] == 'POST':
            logger.info(f"[LLM Static] Testing POST request {index}/{total}")
            logger.info(f"[LLM Static] POST URL: {test_case['url']}")
            logger.info(f"[LLM Static] POST data: {test_case['data']}")
            return requests.post(test_case['url'], data=test_case['data'], timeout=10)

        logger.info(f"[LLM Static] Testing GET request {index}/{total}")
        logger.info(f"[LLM Static] GET URL: {test_case['url'][:150]}")
        return requests.get(test_case['url'], timeout=10)

