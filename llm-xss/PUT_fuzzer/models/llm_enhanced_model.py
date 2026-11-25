"""
LLM增强XSS测试模块。

本模块保留兼容类和两个公共入口；具体职责由三个 Mixin 实现。
"""

import os
from typing import List, Dict, Optional
import logging

from .llm_payload import LLMPayloadMixin
from .llm_request import LLMRequestMixin
from .llm_verify import LLMVerifyMixin

logger = logging.getLogger(__name__)


class LLMEnhancedTester(
    LLMPayloadMixin,
    LLMRequestMixin,
    LLMVerifyMixin,
):
    """向后兼容的 LLM 增强测试器。"""


def _with_failed_response(result: Dict, llm_tester: Optional[LLMEnhancedTester]) -> Dict:
    if llm_tester is not None and isinstance(llm_tester._llm_response, str):
        result["failed_response"] = llm_tester._llm_response
    return result


def llm_enhanced_test(tester, 
                     test_put_path: str, 
                     context_info: Dict,
                     standard_payloads: List[str] = None,
                     provider: str = 'qwen',
                     api_key: str = None,
                     api_base: str = None,
                     model: str = None,
                     max_payloads: int = 15) -> Dict:
    """
    便捷函数：执行完整的LLM增强测试流程
    
    Args:
        tester: Sanitizer_Tester实例
        test_put_path: PUT文件路径
        context_info: 上下文信息
        standard_payloads: 标准测试中已尝试的payload
        provider: LLM提供商
        api_key: API密钥
        model: 模型名称
        max_payloads: 最多生成的payload数量
    
    Returns:
        测试结果字典
    """
    llm_tester = None
    try:
        # 初始化LLM测试器
        llm_tester = LLMEnhancedTester(
            provider=provider,
            api_key=api_key,
            api_base=api_base,
            model=model
        )
        
        # 分析PHP代码
        analysis = llm_tester.analyze_php_code(test_put_path, context_info)
        
        # 生成定制payload
        custom_payloads = llm_tester.generate_custom_payloads(
            analysis, 
            standard_payloads or [],
            max_payloads
        )
        
        if not custom_payloads:
            logger.warning("No custom payloads generated")
            return _with_failed_response(llm_tester._build_no_payload_result(), llm_tester)
        
        # 测试定制payload
        found, successful_payload, test_count = llm_tester.test_custom_payloads(
            tester,
            test_put_path,
            custom_payloads,
            context_info
        )
        
        return llm_tester._build_enhanced_result(
            found,
            successful_payload,
            custom_payloads,
            test_count,
            analysis,
            context_info,
        )
    
    except Exception as e:
        logger.error(f"LLM enhanced test failed: {e}")
        import traceback
        traceback.print_exc()
        result = {
            "vulnerability_found": False,
            "successful_payload": None,
            "custom_payloads_generated": 0,
            "custom_payloads_tested": 0,
            "error": str(e)
        }
        return _with_failed_response(result, llm_tester)


def llm_static_analysis_test(tester,
                             test_put_path: str,
                             provider: str = 'qwen',
                             api_key: str = None,
                             api_base: str = None,
                             model: str = None,
                             max_payloads: int = 20) -> Dict:
    """
    专门用于"Could not parse context"文件的LLM静态分析测试
    不依赖context_parser，直接分析PHP代码生成payload
    
    Args:
        tester: Sanitizer_Tester实例
        test_put_path: PUT文件路径
        provider: LLM提供商
        api_key: API密钥
        model: 模型名称
        max_payloads: 最多生成的payload数量
    
    Returns:
        测试结果字典
    """
    logger.info(f"[LLM Static] Starting static analysis test for {test_put_path}")
    
    llm_tester = None
    try:
        # 初始化LLM测试器
        llm_tester = LLMEnhancedTester(
            provider=provider,
            api_key=api_key,
            api_base=api_base,
            model=model
        )
        
        # 读取PHP代码
        try:
            with open(test_put_path, 'r', encoding='utf-8', errors='ignore') as f:
                php_code = f.read()
        except Exception as e:
            logger.error(f"Failed to read PHP file: {e}")
            return {
                "vulnerability_found": False,
                "successful_payload": None,
                "custom_payloads_generated": 0,
                "custom_payloads_tested": 0,
                "error": f"Failed to read file: {e}"
            }
        
        # 读取函数定义文件
        function_def_path = test_put_path.replace("index.php", "function_definition.php")
        function_code = ""
        if os.path.exists(function_def_path):
            try:
                with open(function_def_path, 'r', encoding='utf-8', errors='ignore') as f:
                    function_code = f.read()
            except Exception as e:
                logger.warning(f"Failed to read function definition: {e}")
        
        # 静态分析PHP代码
        static_analysis = llm_tester._static_code_analysis(php_code, function_code)
        
        logger.info(f"[LLM Static] Found {len(static_analysis['input_params'])} input params, "
                   f"{len(static_analysis['output_points'])} output points")
        
        # 使用LLM生成针对性payload
        custom_payloads = llm_tester._generate_payloads_from_static_analysis(
            static_analysis,
            max_payloads
        )
        
        if not custom_payloads:
            logger.warning("[LLM Static] No payloads generated")
            return _with_failed_response(
                llm_tester._build_no_payload_result(static_analysis), llm_tester,
            )
        
        logger.info(f"[LLM Static] Generated {len(custom_payloads)} payloads, starting tests...")
        
        # 测试payload（不依赖context）
        found, successful_payload, test_count = llm_tester._test_payloads_without_context(
            tester,
            test_put_path,
            custom_payloads,
            static_analysis
        )
        
        result = llm_tester._build_static_result(
            found,
            successful_payload,
            custom_payloads,
            test_count,
            static_analysis,
        )
        
        if found:
            logger.info(f"[LLM Static] ✅ Vulnerability found: {successful_payload}")
        else:
            logger.info(f"[LLM Static] No vulnerability found after {test_count} tests")
        
        return result
    
    except Exception as e:
        logger.error(f"[LLM Static] Test failed: {e}")
        import traceback
        traceback.print_exc()
        result = {
            "vulnerability_found": False,
            "successful_payload": None,
            "custom_payloads_generated": 0,
            "custom_payloads_tested": 0,
            "error": str(e)
        }
        return _with_failed_response(result, llm_tester)


