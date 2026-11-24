"""
LLM Payload 验证模块。

负责测试调度、响应验证、浏览器验证调用、测试计数与结果组装。
"""

import json
from typing import List, Dict, Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class LLMVerifyMixin:
    def _test_payloads_without_context(self, tester, test_put_path: str,
                                      payloads: List[str], analysis: Dict,
                                      parallel: bool = True,
                                      max_workers: int = 4) -> Tuple[bool, Optional[str], int]:
        """
        测试payload，不依赖context信息
        支持并行测试以提升效率
        
        使用宽松的验证标准：只要payload成功注入到响应中且未被编码，就判定为漏洞
        这更符合XSS的学术定义，避免因无法触发alert而漏报
        
        Args:
            tester: Sanitizer_Tester实例
            test_put_path: PUT文件路径
            payloads: payload列表
            analysis: 静态分析结果
            parallel: 是否启用并行测试（默认True）
            max_workers: 并行线程数（默认4）
        
        Returns:
            (是否发现漏洞, 成功的payload, 测试次数)
        """
        from .config_model import fuzz_cases
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import threading
        
        logger.info(f"[LLM Static] Testing {len(payloads)} payloads without context (parallel={parallel}, workers={max_workers})...")
        logger.info(f"[LLM Static] Using relaxed validation: payload injection detection")
        
        # 只使用第一个fuzz_case以控制测试时间
        if not fuzz_cases:
            logger.warning("[LLM Static] No fuzz_cases available")
            return False, None, 0
        
        fuzz_case = fuzz_cases[0]
        if isinstance(fuzz_case, bytes):
            import base64
            fuzz_case_json = json.dumps(base64.b64encode(fuzz_case).decode('utf-8'))
        else:
            fuzz_case_json = json.dumps(fuzz_case)
        
        # 串行模式（向后兼容或payload数量少时）
        if not parallel or len(payloads) <= 2:
            test_count = 0
            for i, payload in enumerate(payloads, 1):
                logger.info(f"[LLM Static] Testing payload {i}/{len(payloads)}: {payload[:60]}...")
                test_count += 1
                try:
                    is_vulnerable, detection_method = self._verify_payload_injection(
                        tester, test_put_path, payload, fuzz_case_json, analysis
                    )
                    if is_vulnerable:
                        logger.info(f"[LLM Static] ✅ Vulnerability found with payload: {payload}")
                        logger.info(f"[LLM Static] Detection method: {detection_method}")
                        return True, payload, test_count
                except Exception as e:
                    logger.warning(f"[LLM Static] Error testing payload {i}: {e}")
                    continue
            logger.info(f"[LLM Static] No vulnerability found after {test_count} tests")
            return False, None, test_count
        
        # 并行模式
        found_event = threading.Event()
        test_count_lock = threading.Lock()
        test_count_container = [0]
        found_result_container = [None, None]  # [payload, detection_method]
        
        def test_single_payload_static(payload_info):
            """测试单个payload的线程函数（静态分析模式）"""
            idx, payload = payload_info
            
            if found_event.is_set():
                return None
            
            logger.debug(f"[LLM Static Parallel] Testing payload {idx}/{len(payloads)}: {payload[:60]}...")
            
            try:
                is_vulnerable, detection_method = self._verify_payload_injection(
                    tester, test_put_path, payload, fuzz_case_json, analysis
                )
                
                with test_count_lock:
                    test_count_container[0] += 1
                
                if is_vulnerable:
                    found_event.set()
                    found_result_container[0] = payload
                    found_result_container[1] = detection_method
                    logger.info(f"[LLM Static Parallel] ✅ Vulnerability found with payload: {payload}")
                    logger.info(f"[LLM Static Parallel] Detection method: {detection_method}")
                    return payload
                    
            except Exception as e:
                logger.warning(f"[LLM Static Parallel] Error testing payload {idx}: {e}")
                with test_count_lock:
                    test_count_container[0] += 1
            
            return None
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(test_single_payload_static, (i, payload)): payload
                for i, payload in enumerate(payloads, 1)
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=60)
                    if result is not None:
                        for f in futures:
                            f.cancel()
                        return True, found_result_container[0], test_count_container[0]
                except Exception as e:
                    logger.debug(f"[LLM Static Parallel] Future exception: {e}")
        
        logger.info(f"[LLM Static Parallel] No vulnerability found after {test_count_container[0]} tests")
        return False, None, test_count_container[0]
    
    def _verify_payload_injection(self, tester, test_put_path: str, 
                                  payload: str, fuzz_case_json: str, analysis: Dict = None) -> Tuple[bool, str]:
        """
        验证payload是否成功注入（宽松标准，用于LLM静态分析）
        
        验证策略（按优先级）：
        1. 尝试触发alert（最严格）
        2. 检查payload是否在响应中且未被HTML编码（宽松）
        3. 检查payload是否在可执行上下文中（中等）
        
        支持GET和POST请求方法
        
        Args:
            tester: Sanitizer_Tester实例
            test_put_path: PUT文件路径
            payload: 测试payload
            fuzz_case_json: fuzz case JSON字符串
            analysis: 静态分析结果（可选，用于获取正确的参数名）
        
        Returns:
            (是否存在漏洞, 检测方法)
        """
        # 方法1: 尝试标准bugoracle验证（触发alert）
        try:
            if tester.bugoracle(test_put_path, payload, fuzz_case_json):
                return True, "alert_triggered"
        except Exception as e:
            logger.debug(f"[LLM Static] bugoracle failed: {e}")
        # 方法2: 检查payload注入（宽松标准）
        # 尝试多种参数格式和请求方法
        try:
            request_context = self._prepare_payload_requests(
                test_put_path, payload, analysis
            )
            uses_safe_encoding = request_context["uses_safe_encoding"]
            test_cases = request_context["test_cases"]

            # 按原顺序逐个发送并立即验证，命中后立即返回
            for i, test_case in enumerate(test_cases, 1):
                try:
                    response = self._execute_request_case(
                        test_case, i, len(test_cases)
                    )
                    response_text = response.text
                    logger.info(f"[LLM Static] Response status: {response.status_code}")
                    logger.info(f"[LLM Static] Response length: {len(response_text)} chars")
                    logger.debug(f"[LLM Static] Response preview: {response_text[:200]}")
                    
                    # 检查payload是否在响应中
                    if payload in response_text:
                        logger.info(f"[LLM Static] Payload found in response (unencoded)")
                        
                        # 检查是否被HTML编码（仅当payload包含<>时才检查）
                        if '<' in payload or '>' in payload:
                            encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
                            if encoded_payload in response_text and payload not in response_text:
                                logger.info(f"[LLM Static] Payload is HTML encoded (safe)")
                                continue  # 尝试下一个格式
                        
                        # 检查payload是否在JavaScript上下文中（更危险）
                        js_contexts = [
                            f"location='{payload}'",
                            f'location="{payload}"',
                            f"location={payload}",
                            f"<script>{payload}",
                            f"<script type=\"text/javascript\">{payload}",
                            f"onclick=\"{payload}",
                            f"onclick='{payload}",
                            f"onerror=\"{payload}",
                            f"onerror='{payload}",
                            f"onload=\"{payload}",
                            f"onload='{payload}",
                            f"javascript:{payload}",
                            f"eval({payload}",
                            f"eval('{payload}",
                            f'eval("{payload}',
                            f"setTimeout({payload}",
                            f"setTimeout('{payload}",
                            f'setTimeout("{payload}',
                            f"setInterval({payload}",
                        ]
                        
                        in_js_context = any(ctx in response_text for ctx in js_contexts)
                        
                        if in_js_context:
                            logger.info(f"[LLM Static] Payload found in JavaScript context (VULNERABLE)")
                            logger.info(f"[LLM Static] Successful method: {test_case['method']}")
                            logger.info(f"[LLM Static] Successful URL: {test_case['url'][:100]}")
                            return True, f"payload_in_js_context_{test_case['method']}"
                        
                        # 检查payload是否在危险的HTML属性上下文中
                        dangerous_attr_contexts = [
                            f'href="{payload}"',
                            f"href='{payload}'",
                            f'href={payload}',
                            f'src="{payload}"',
                            f"src='{payload}'",
                            f'src={payload}',
                            f'action="{payload}"',
                            f"action='{payload}'",
                            f'action={payload}',
                            f'data="{payload}"',
                            f"data='{payload}'",
                            f'formaction="{payload}"',
                            f"formaction='{payload}'",
                        ]
                        
                        in_dangerous_attr = any(ctx in response_text for ctx in dangerous_attr_contexts)
                        
                        if in_dangerous_attr:
                            logger.info(f"[LLM Static] Payload found in dangerous attribute context (VULNERABLE)")
                            logger.info(f"[LLM Static] Successful method: {test_case['method']}")
                            logger.info(f"[LLM Static] Successful URL: {test_case['url'][:100]}")
                            return True, f"payload_in_dangerous_attr_{test_case['method']}"
                        
                        # 检查是否被JSON编码（新增）
                        if uses_safe_encoding is None:
                            # 保留原代码在 PHP 文件读取失败时的异常降级行为。
                            raise UnboundLocalError(
                                "local variable 'uses_safe_encoding' referenced before assignment"
                            )
                        if uses_safe_encoding:
                            # 检查响应是否是JSON格式
                            try:
                                import json as json_module
                                json_data = json_module.loads(response_text)
                                # 如果能成功解析为JSON，说明使用了json_encode
                                logger.info(f"[LLM Static] Response is valid JSON (likely json_encode)")
                                
                                # JSON编码的关键：payload在JSON字符串中是安全的
                                # 因为JSON字符串会被正确解析，不会被浏览器当作HTML执行
                                # 即使<>没有被转义，也是安全的
                                
                                # 检查payload是否在JSON的字符串值中（而不是键或结构中）
                                def check_payload_in_json_values(obj, payload):
                                    """递归检查payload是否在JSON的值中"""
                                    if isinstance(obj, dict):
                                        for value in obj.values():
                                            if check_payload_in_json_values(value, payload):
                                                return True
                                    elif isinstance(obj, list):
                                        for item in obj:
                                            if check_payload_in_json_values(item, payload):
                                                return True
                                    elif isinstance(obj, str):
                                        if payload in obj:
                                            return True
                                    return False
                                
                                if check_payload_in_json_values(json_data, payload):
                                    logger.info(f"[LLM Static] Payload found in JSON string value (safe)")
                                    logger.debug(f"[LLM Static] JSON encoding protects payload from execution")
                                    continue  # 安全，尝试下一个测试用例
                                
                            except Exception as e:
                                # 不是有效的JSON，继续检查
                                logger.debug(f"[LLM Static] Not valid JSON or error: {e}")
                                pass
                        
                        # 对于包含<>的payload，如果未被编码则是漏洞
                        if '<' in payload or '>' in payload:
                            logger.info(f"[LLM Static] Payload with HTML tags injected without encoding (vulnerable)")
                            logger.info(f"[LLM Static] Successful method: {test_case['method']}")
                            logger.info(f"[LLM Static] Successful URL: {test_case['url'][:100]}")
                            return True, f"payload_injected_unencoded_{test_case['method']}"
                        
                        # 对于不含<>的payload（如javascript:alert()），如果只是纯文本输出则安全
                        logger.info(f"[LLM Static] Payload found in response but in safe text context (not vulnerable)")
                        logger.debug(f"[LLM Static] Payload '{payload}' appears as plain text without dangerous context")
                        continue  # 尝试下一个测试用例
                    
                    # 检查是否被部分编码
                    if '<' in payload and '&lt;' in response_text:
                        logger.debug(f"[LLM Static] Payload appears to be encoded in this format")
                        continue
                    
                except Exception as e:
                    logger.warning(f"[LLM Static] Error testing case {i}: {e}")
                    import traceback
                    logger.debug(traceback.format_exc())
                    continue
            logger.info(f"[LLM Static] Payload not found in response (tried {len(test_cases)} formats)")
            return False, "payload_not_found"
            
        except Exception as e:
            logger.warning(f"[LLM Static] Error checking payload injection: {e}")
            return False, f"error_{str(e)[:20]}"
    def test_custom_payloads(self, 
                            tester, 
                            test_put_path: str, 
                            custom_payloads: List[str], 
                            context: Dict,
                            parallel: bool = True,
                            max_workers: int = 4) -> Tuple[bool, Optional[str], int]:
        """
        测试LLM生成的定制payload
        支持并行测试以提升效率，使用与原代码完全相同的验证流程
        
        Args:
            tester: Sanitizer_Tester实例
            test_put_path: PUT文件路径
            custom_payloads: 定制payload列表
            context: 上下文信息
            parallel: 是否启用并行测试（默认True）
            max_workers: 并行线程数（默认4）
        
        Returns:
            (是否发现漏洞, 成功的payload, 测试次数)
        """
        from .config_model import fuzz_cases, feedback_dir
        from .helper_model import clear_log_files
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import threading
        
        logger.info(f"Testing {len(custom_payloads)} custom payloads (parallel={parallel}, workers={max_workers})...")
        
        position = context.get('position', 'unknown')
        
        # 串行模式（向后兼容）
        if not parallel or len(custom_payloads) <= 2:
            test_count = 0
            for i, payload in enumerate(custom_payloads, 1):
                logger.debug(f"Testing payload {i}/{len(custom_payloads)}: {payload[:50]}...")
                try:
                    init_vector = payload
                    if tester.bugoracle_pro(test_put_path, payload, position, init_vector):
                        test_count += len(fuzz_cases)
                        logger.info(f"✅ Vulnerability found with LLM payload: {payload}")
                        return True, payload, test_count
                    test_count += len(fuzz_cases)
                except Exception as e:
                    logger.warning(f"Error testing payload {i}: {e}")
                    test_count += len(fuzz_cases)
                    continue
            logger.info(f"No vulnerability found with {len(custom_payloads)} custom payloads")
            return False, None, test_count
        
        # 并行模式
        found_event = threading.Event()  # 用于通知其他线程停止
        test_count_lock = threading.Lock()
        test_count_container = [0]  # 使用列表以便在闭包内修改
        found_payload_container = [None]
        
        def test_single_payload(payload_info):
            """测试单个payload的线程函数"""
            idx, payload = payload_info
            
            # 如果已经找到漏洞，跳过
            if found_event.is_set():
                return None
            
            logger.debug(f"[Parallel] Testing payload {idx}/{len(custom_payloads)}: {payload[:50]}...")
            
            try:
                init_vector = payload
                result = tester.bugoracle_pro(test_put_path, payload, position, init_vector)
                
                with test_count_lock:
                    test_count_container[0] += len(fuzz_cases)
                
                if result:
                    found_event.set()  # 通知其他线程停止
                    found_payload_container[0] = payload
                    logger.info(f"✅ [Parallel] Vulnerability found with LLM payload: {payload}")
                    return payload
                    
            except Exception as e:
                logger.warning(f"[Parallel] Error testing payload {idx}: {e}")
                with test_count_lock:
                    test_count_container[0] += len(fuzz_cases)
            
            return None
        
        # 提交并行任务
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(test_single_payload, (i, payload)): payload
                for i, payload in enumerate(custom_payloads, 1)
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=120)
                    if result is not None:
                        # 找到漏洞，取消剩余任务
                        for f in futures:
                            f.cancel()
                        return True, found_payload_container[0], test_count_container[0]
                except Exception as e:
                    logger.debug(f"[Parallel] Future exception: {e}")
        
        logger.info(f"No vulnerability found with {len(custom_payloads)} custom payloads (parallel)")
        return False, None, test_count_container[0]



    def _build_no_payload_result(self, static_analysis: Dict = None) -> Dict:
        """组装未生成 Payload 时的既有结果字典。"""
        result = {
            "vulnerability_found": False,
            "successful_payload": None,
            "custom_payloads_generated": 0,
            "custom_payloads_tested": 0,
            "error": "No payloads generated",
        }
        if static_analysis is not None:
            result["static_analysis"] = static_analysis
        return result

    def _build_enhanced_result(
        self,
        found: bool,
        successful_payload: Optional[str],
        custom_payloads: List[str],
        test_count: int,
        analysis: Dict,
        context_info: Dict,
    ) -> Dict:
        """组装常规 LLM 测试的既有结果字典。"""
        return {
            "vulnerability_found": found,
            "successful_payload": successful_payload,
            "custom_payloads_generated": len(custom_payloads),
            "custom_payloads_tested": test_count,
            "analysis": {
                "sanitizers_count": len(analysis['sanitizers']),
                "filters_count": len(analysis['filters']),
                "context_type": context_info.get('context', 'unknown')
            }
        }

    def _build_static_result(
        self,
        found: bool,
        successful_payload: Optional[str],
        custom_payloads: List[str],
        test_count: int,
        static_analysis: Dict,
    ) -> Dict:
        """组装静态分析测试的既有结果字典。"""
        return {
            "vulnerability_found": found,
            "successful_payload": successful_payload,
            "custom_payloads_generated": len(custom_payloads),
            "custom_payloads_tested": test_count,
            "method": "llm_static_analysis",
            "static_analysis": {
                "input_params": static_analysis['input_params'],
                "output_points": static_analysis['output_points'],
                "sanitizers": len(static_analysis['sanitizers']),
                "filters": len(static_analysis['filters'])
            }
        }

