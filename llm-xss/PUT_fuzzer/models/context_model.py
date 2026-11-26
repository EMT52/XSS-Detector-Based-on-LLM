from .Tag_model import TagsCharacters
from .javascript_model import JavaScriptCodeCharacters
from .protocol_model import SchemeTriggerCharacters
from .parser_model import context_parser
from .config_model import unique_probe, fuzz_cases
from .attribute_model import attribute_attackgrammar
from .llm_enhanced_model import llm_enhanced_test
import json
import traceback
import logging
import threading

logger = logging.getLogger(__name__)

class TimeoutException(Exception):
    """超时异常"""
    pass


def timeout_handler(func, args=(), kwargs={}, timeout_duration=120, default=None):
    """
    跨平台的超时处理函数
    
    Args:
        func: 要执行的函数
        args: 函数参数
        kwargs: 函数关键字参数
        timeout_duration: 超时时间（秒）
        default: 超时时返回的默认值
    
    Returns:
        函数执行结果或默认值
    """
    class InterruptableThread(threading.Thread):
        def __init__(self):
            threading.Thread.__init__(self)
            self.result = default
            self.exception = None
            self.daemon = True  # 设置为守护线程，主线程结束时自动结束

        def run(self):
            try:
                self.result = func(*args, **kwargs)
            except Exception as e:
                self.exception = e

    it = InterruptableThread()
    it.start()
    it.join(timeout_duration)
    
    if it.is_alive():
        # 超时了，尝试清理资源
        logger.warning(f"Thread timed out after {timeout_duration}s, attempting cleanup...")
        try:
            import subprocess
            # 清理可能卡住的Chrome进程
            subprocess.run(['pkill', '-9', 'chrome'], stderr=subprocess.DEVNULL, timeout=1)
            subprocess.run(['pkill', '-9', 'chromedriver'], stderr=subprocess.DEVNULL, timeout=1)
        except Exception:
            pass  # 清理失败也不影响
        
        raise TimeoutException(f"Function execution exceeded {timeout_duration}s")
    
    if it.exception:
        raise it.exception
    
    return it.result


Tags = TagsCharacters()
code = JavaScriptCodeCharacters()
schemetrigger = SchemeTriggerCharacters()

class context:
    def __init__(self, tester, enable_llm=False, llm_provider='qwen', 
                 llm_api_key=None, llm_model=None, llm_api_base=None):
        self.tester = tester
        self.enable_llm = enable_llm
        self.llm_provider = llm_provider
        self.llm_api_key = llm_api_key
        self.llm_model = llm_model
        self.llm_api_base = llm_api_base
    
    def test_put(self, test_put_path, results, timeout=120):
        """
        测试单个PUT文件，带超时保护
        
        Args:
            test_put_path: 测试文件路径
            results: 结果字典
            timeout: 超时时间（秒）
        
        Returns:
            更新后的results字典
        """
        # 标准测试阶段 - 使用timeout_handler包装
        try:
            # 使用timeout_handler包装_test_put_impl，提供真正的超时保护
            return timeout_handler(
                self._test_put_impl,
                args=(test_put_path, results, timeout),
                timeout_duration=timeout
            )
        except TimeoutException as e:
            logger.warning(f"[TIMEOUT] Standard test for {test_put_path} exceeded {timeout}s")
            
            # 超时的文件标记为safe，等待后续的LLM批量测试
            results["safe_files"][test_put_path] = {
                "test_count": 0,
                "error": f"timeout_{timeout}s"
            }
            return results
    
    def _try_llm_after_timeout(self, test_put_path, timeout=60):
        """
        在标准测试超时后尝试LLM测试
        
        Args:
            test_put_path: 测试文件路径
            timeout: LLM测试的超时时间
        
        Returns:
            LLM测试结果或None
        """
        try:
            # 遍历所有fuzz_cases获取上下文（仿照标准测试）
            from .config_model import unique_probe, fuzz_cases
            
            if not fuzz_cases:
                return {"error": "No fuzz cases available for LLM testing", "failed_response": None}
            
            context_db = None
            successful_fuzz_case_index = -1
            
            # 遍历所有fuzz_cases，找到能解析出context的
            for idx, fuzz_case in enumerate(fuzz_cases):
                try:
                    if isinstance(fuzz_case, bytes):
                        import base64
                        fuzz_case_json = json.dumps(base64.b64encode(fuzz_case).decode('utf-8'))
                    else:
                        fuzz_case_json = json.dumps(fuzz_case)
                    
                    response = self.tester.test_filter(test_put_path, unique_probe, fuzz_case_json)
                    context_db = context_parser(response)
                    
                    if context_db:
                        successful_fuzz_case_index = idx
                        logger.info(f"[LLM] ✅ Found context with fuzz_case[{idx}]")
                        break  # 找到就停止
                except Exception as e:
                    logger.debug(f"[LLM] fuzz_case[{idx}] failed: {e}")
                    continue
            
            # 只有所有fuzz_cases都无法解析context时，才使用静态分析模式
            if not context_db:
                logger.warning(f"[LLM] Could not parse context with any of {len(fuzz_cases)} fuzz_cases, trying static analysis mode...")
                # 使用静态分析模式
                from .llm_enhanced_model import llm_static_analysis_test
                
                llm_result = llm_static_analysis_test(
                    self.tester,
                    test_put_path,
                    provider=self.llm_provider,
                    api_key=self.llm_api_key,
                    api_base=self.llm_api_base,
                    model=self.llm_model,
                    max_payloads=10  # 减少到10个payload以控制测试时间
                )
                
                return llm_result
            
            # 获取第一个context
            first_context_key = list(context_db.keys())[0]
            first_context = context_db[first_context_key]
            
            logger.info(f"[LLM] Using context type: {first_context.get('context', 'unknown')}")
            
            # 调用LLM测试
            llm_result = llm_enhanced_test(
                self.tester, 
                test_put_path, 
                first_context,
                standard_payloads=[],
                provider=self.llm_provider,
                api_key=self.llm_api_key,
                api_base=self.llm_api_base,
                model=self.llm_model,
                max_payloads=10  # 减少payload数量以加快速度
            )
            
            return llm_result
            
        except Exception as e:
            logger.error(f"[LLM] Error in _try_llm_after_timeout: {e}")
            return {"error": f"{type(e).__name__}: {e}", "failed_response": None}
    
    def _test_put_impl(self, test_put_path, results, timeout=120):
        context = []
        vectors = {}
        max_test_count = 0  # 跟踪最大的 test_count
        found_context = False  # 标记是否找到过上下文
        standard_error = None

        for fuzz_case in fuzz_cases:
            try:
                # 修复：处理 bytes 类型，转换为 base64 字符串
                if isinstance(fuzz_case, bytes):
                    import base64
                    fuzz_case_json = json.dumps(base64.b64encode(fuzz_case).decode('utf-8'))
                else:
                    fuzz_case_json = json.dumps(fuzz_case)
                
                response = self.tester.test_filter(test_put_path, unique_probe, fuzz_case_json)
                context_db = context_parser(response)
                if context_db:
                    found_context = True  # 标记找到了上下文
                    for i in context_db:
                        context_type = context_db[i]['context']  # 改名避免与类名冲突
                        test_count = 0
                        
                        try:
                            if context_type == 'html':
                                vectors, test_count = Tags.html_attackgrammar(self.tester, context_db[i], test_put_path)
                            elif context_type == 'attribute':
                                vectors, test_count = attribute_attackgrammar(self.tester, context_db[i], test_put_path)
                            elif context_type == 'protocols':
                                vectors, test_count = schemetrigger.url_attackgrammar(self.tester, context_db[i], test_put_path)
                            elif context_type == 'script':
                                script_context = code.script_parser(response)
                                vectors, test_count = code.script_attackgrammar(self.tester, script_context , context_db[i], test_put_path)
                            
                            # 更新最大 test_count
                            max_test_count = max(max_test_count, test_count)
                            
                            if vectors:
                                results["vulnerable_files"][test_put_path] = {
                                    "note": "Vulnerability found by standard test",
                                    "payload": vectors,
                                    "test_count": test_count
                                }
                                return results
                        except Exception as e:
                            # attackgrammar 出错(如缺少 chromedriver),但仍然算作进行了测试
                            logger.debug(f"attackgrammar failed for {test_put_path}: {e}")
                            standard_error = str(e) or type(e).__name__
                            max_test_count = max(max_test_count, 1)
            except Exception as e:
                # test_filter 或 context_parser 出错,静默跳过
                logger.debug(f"test_filter or context_parser failed: {e}")
                standard_error = str(e) or type(e).__name__
                pass
        
        # 标准测试结束，未找到漏洞
        # 标记为safe，等待后续的LLM批量测试
        if found_context:
            # 找到过上下文但没有漏洞
            results["safe_files"][test_put_path] = {
                "test_count": max_test_count
            }
            if standard_error:
                results["safe_files"][test_put_path]["error"] = standard_error
        else:
            # 从未找到上下文
            results["safe_files"][test_put_path] = {
                "test_count": 0,
                "error": standard_error or "Could not parse context"
            }
        
        return results
