"""
LLM Payload 构造模块。

负责程序特征提取、Prompt 构造、模型调用、输出解析与 Payload 生成。
"""

import json
import os
import re
import requests
from typing import List, Dict, Tuple, Optional
import logging

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LLMPayloadMixin:
    """
    使用大模型增强XSS测试的核心类
    支持多种LLM服务提供商
    """
    
    # 支持的LLM提供商
    SUPPORTED_PROVIDERS = {
        'qwen': 'Alibaba Qwen (通义千问)',
        'ernie': 'Baidu ERNIE (文心一言)', 
        'zhipu': 'Zhipu AI (智谱AI)',
        'deepseek': 'DeepSeek',
        'openai': 'OpenAI',
        'claude': 'Anthropic Claude',
        'local': 'Local Model (Ollama/LM Studio)'
    }
    
    def __init__(self, 
                 provider: str = 'qwen',
                 api_key: str = None,
                 api_base: str = None,
                 model: str = None):
        """
        初始化LLM测试器
        
        Args:
            provider: LLM提供商 ('qwen', 'ernie', 'zhipu', 'deepseek', 'openai', 'claude', 'local')
            api_key: API密钥
            api_base: API基础URL（可选，用于自定义端点）
            model: 模型名称（可选，使用默认模型）
        """
        self.provider = provider.lower()
        self.api_key = api_key or os.getenv(f"{provider.upper()}_API_KEY")
        self.api_base = api_base
        
        # 设置默认模型
        self.model = model or self._get_default_model()
        
        # 验证配置
        if not self.api_key and self.provider != 'local':
            raise ValueError(f"API key required for {provider}")
        
        logger.info(f"Initialized LLM with provider: {self.provider}, model: {self.model}")
    
    def _get_default_model(self) -> str:
        """获取默认模型名称"""
        defaults = {
            'qwen': 'qwen-max',
            'ernie': 'ernie-4.0-8k',
            'zhipu': 'glm-4',
            'deepseek': 'deepseek-chat',
            'openai': 'gpt-4',
            'claude': 'claude-3-opus-20240229',
            'local': 'llama2'
        }
        return defaults.get(self.provider, 'gpt-4')
    
    def analyze_php_code(self, php_file_path: str, context_info: Dict) -> Dict:
        """
        分析PHP代码，提取关键特征
        
        Args:
            php_file_path: PHP文件路径
            context_info: 上下文信息（从context_parser获取）
        
        Returns:
            分析结果字典
        """
        logger.info(f"Analyzing PHP code: {php_file_path}")
        
        # 读取主PHP代码
        try:
            with open(php_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                php_code = f.read()
        except Exception as e:
            logger.error(f"Failed to read PHP file: {e}")
            php_code = ""
        
        # 读取函数定义文件
        function_def_path = php_file_path.replace("index.php", "function_definition.php")
        function_code = ""
        if os.path.exists(function_def_path):
            try:
                with open(function_def_path, 'r', encoding='utf-8', errors='ignore') as f:
                    function_code = f.read()
            except Exception as e:
                logger.warning(f"Failed to read function definition file: {e}")
        
        # 合并代码用于分析
        full_code = php_code + "\n" + function_code
        
        # 提取各种特征
        analysis = {
            "php_code": php_code[:2000],  # 限制长度避免token超限
            "function_code": function_code[:1000],
            "context": context_info,
            "sanitizers": self._extract_sanitizers(full_code),
            "filters": self._extract_filters(full_code),
            "encoding_functions": self._extract_encoding_functions(full_code),
            "dangerous_functions": self._extract_dangerous_functions(full_code),
            "code_patterns": self._extract_code_patterns(full_code)
        }
        
        logger.info(f"Analysis complete. Found {len(analysis['sanitizers'])} sanitizers, "
                   f"{len(analysis['filters'])} filters")
        
        return analysis
    
    def _extract_sanitizers(self, code: str) -> List[Dict]:
        """提取代码中的净化器函数及其参数"""
        sanitizer_patterns = {
            'htmlspecialchars': r'htmlspecialchars\s*\(([^)]+)\)',
            'htmlentities': r'htmlentities\s*\(([^)]+)\)',
            'strip_tags': r'strip_tags\s*\(([^)]+)\)',
            'filter_var': r'filter_var\s*\(([^)]+)\)',
            'preg_replace': r'preg_replace\s*\(([^)]+)\)',
            'str_replace': r'str_replace\s*\(([^)]+)\)',
            'addslashes': r'addslashes\s*\(([^)]+)\)',
            'mysql_real_escape_string': r'mysql_real_escape_string\s*\(([^)]+)\)'
        }
        
        found_sanitizers = []
        for func_name, pattern in sanitizer_patterns.items():
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                found_sanitizers.append({
                    'function': func_name,
                    'params': match.group(1).strip()[:100]  # 限制参数长度
                })
        
        return found_sanitizers
    
    def _extract_filters(self, code: str) -> List[Dict]:
        """提取代码中的过滤逻辑"""
        filters = []
        
        # 查找preg_match模式
        preg_matches = re.finditer(r'preg_match\s*\(\s*[\'"]([^\'"]+)[\'"]', code)
        for match in preg_matches:
            filters.append({
                'type': 'preg_match',
                'pattern': match.group(1)[:100]
            })
        
        # 查找str_replace模式
        str_replaces = re.finditer(r'str_replace\s*\(\s*[\'"]([^\'"]+)[\'"]', code)
        for match in str_replaces:
            filters.append({
                'type': 'str_replace',
                'pattern': match.group(1)[:50]
            })
        
        return filters[:10]  # 最多返回10个
    
    def _extract_encoding_functions(self, code: str) -> List[str]:
        """提取编码函数"""
        encoding_patterns = [
            r'urlencode\s*\(',
            r'rawurlencode\s*\(',
            r'base64_encode\s*\(',
            r'json_encode\s*\(',
            r'bin2hex\s*\('
        ]
        
        encoding_funcs = []
        for pattern in encoding_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                func_name = pattern.replace(r'\s*\(', '').replace(r'\\', '')
                encoding_funcs.append(func_name)
        
        return encoding_funcs
    
    def _extract_dangerous_functions(self, code: str) -> List[str]:
        """提取可能导致XSS的危险函数"""
        dangerous = []
        patterns = {
            'echo': r'\becho\s+',
            'print': r'\bprint\s+',
            'printf': r'\bprintf\s*\(',
            'eval': r'\beval\s*\(',
        }
        
        for func, pattern in patterns.items():
            if re.search(pattern, code):
                dangerous.append(func)
        
        return dangerous
    
    def _extract_code_patterns(self, code: str) -> Dict:
        """提取代码模式特征"""
        return {
            'has_quotes_escape': bool(re.search(r'addslashes|mysql_real_escape_string', code)),
            'has_html_encode': bool(re.search(r'htmlspecialchars|htmlentities', code)),
            'has_tag_strip': bool(re.search(r'strip_tags', code)),
            'has_regex_filter': bool(re.search(r'preg_replace|preg_match', code)),
            'has_string_replace': bool(re.search(r'str_replace|str_ireplace', code)),
        }
    
    def generate_custom_payloads(self, 
                                analysis: Dict, 
                                standard_payloads: List[str],
                                max_payloads: int = 15) -> List[str]:
        """
        使用LLM生成定制化的payload
        
        Args:
            analysis: PHP代码分析结果
            standard_payloads: 标准测试中已经尝试的payload
            max_payloads: 最多生成的payload数量
        
        Returns:
            定制化payload列表
        """
        logger.info(f"Generating custom payloads using {self.provider}...")
        
        # 构建prompt
        prompt = self._build_llm_prompt(analysis, standard_payloads, max_payloads)
        
        # 调用LLM API
        try:
            llm_output = self._call_llm_api(prompt)
            
            # 解析LLM响应
            custom_payloads = self._parse_llm_output(llm_output)
            
            logger.info(f"Generated {len(custom_payloads)} custom payloads")
            return custom_payloads[:max_payloads]
            
        except Exception as e:
            logger.error(f"LLM API call failed: {e}")
            return []
    
    def _build_llm_prompt(self, analysis: Dict, standard_payloads: List[str], max_payloads: int) -> str:
        """构建发送给LLM的prompt"""
        
        # 格式化净化器信息
        sanitizers_info = ""
        has_strip_tags = False
        strip_tags_allowed = []
        
        if analysis['sanitizers']:
            sanitizers_info = "检测到的净化器:\n"
            for san in analysis['sanitizers'][:5]:
                sanitizers_info += f"- {san['function']}({san['params'][:50]}...)\n"
                # 检测strip_tags
                if 'strip_tags' in san['function']:
                    has_strip_tags = True
                    # 提取允许的标签
                    import re
                    allowed_match = re.findall(r'<(\w+)>', san['params'])
                    strip_tags_allowed = allowed_match
        else:
            sanitizers_info = "未检测到明显的净化器\n"
        
        # 格式化过滤器信息
        filters_info = ""
        if analysis['filters']:
            filters_info = "检测到的过滤规则:\n"
            for flt in analysis['filters'][:5]:
                filters_info += f"- {flt['type']}: {flt['pattern'][:50]}\n"
        else:
            filters_info = "未检测到过滤规则\n"
        
        # 格式化上下文信息
        context = analysis['context']
        context_type = context.get('context', 'unknown')
        context_details = context.get('details', {})
        
        # 将context_details转换为可序列化的格式
        serializable_details = {}
        for key, value in context_details.items():
            if hasattr(value, 'name'):  # BeautifulSoup Tag对象
                serializable_details[key] = str(value)
            elif isinstance(value, (list, tuple)):
                serializable_details[key] = [str(v) if hasattr(v, 'name') else v for v in value]
            else:
                serializable_details[key] = value
        
        # 格式化标准payload
        standard_payloads_str = ""
        if standard_payloads:
            standard_payloads_str = "已测试的标准payload（前10个）:\n"
            for i, payload in enumerate(standard_payloads[:10], 1):
                standard_payloads_str += f"{i}. {payload[:80]}\n"
        
        # 针对strip_tags的特殊提示
        strip_tags_hint = ""
        if has_strip_tags and strip_tags_allowed:
            strip_tags_hint = f"""
## ⚠️ 重要发现：检测到strip_tags()函数

允许通过的标签: {', '.join(f'<{tag}>' for tag in strip_tags_allowed)}

**关键漏洞点**: strip_tags()只过滤标签，不过滤标签的属性！

**攻击策略**:
1. 使用允许的标签（{', '.join(strip_tags_allowed)}）
2. 在这些标签上添加事件处理器属性
3. 推荐的事件处理器：
   - onmouseover (鼠标悬停触发)
   - onclick (点击触发)
   - onfocus (获得焦点触发)
   - onload (加载触发)
   - onerror (错误触发)
   - onpointerenter (指针进入触发)

**示例payload**:
- <{strip_tags_allowed[0] if strip_tags_allowed else 'b'} onmouseover=alert(711)>hover me</{strip_tags_allowed[0] if strip_tags_allowed else 'b'}>
- <{strip_tags_allowed[0] if strip_tags_allowed else 'b'} onclick=alert(711)>click me</{strip_tags_allowed[0] if strip_tags_allowed else 'b'}>
- <{strip_tags_allowed[0] if strip_tags_allowed else 'b'} onfocus=alert(711) tabindex=1>focus</{strip_tags_allowed[0] if strip_tags_allowed else 'b'}>

你必须生成使用这些允许标签的payload！
"""
        
        prompt = f"""# XSS Payload生成任务

## 目标PHP代码分析

### 主要代码片段:
```php
{analysis['php_code'][:800]}
```

### {sanitizers_info}

### {filters_info}

### 编码函数:
{', '.join(analysis['encoding_functions']) if analysis['encoding_functions'] else '无'}

### 危险输出函数:
{', '.join(analysis['dangerous_functions']) if analysis['dangerous_functions'] else '无'}

### Sink上下文类型:
- 类型: {context_type}
- 位置: {context.get('position', 'unknown')}
- 详细信息: {json.dumps(serializable_details, ensure_ascii=False)[:100]}

### 代码特征:
- 引号转义: {'是' if analysis['code_patterns']['has_quotes_escape'] else '否'}
- HTML编码: {'是' if analysis['code_patterns']['has_html_encode'] else '否'}
- 标签过滤: {'是' if analysis['code_patterns']['has_tag_strip'] else '否'}
- 正则过滤: {'是' if analysis['code_patterns']['has_regex_filter'] else '否'}

{strip_tags_hint}

{standard_payloads_str}

## 你的任务:
查找该php可能出现的漏洞，根据可能的漏洞，并基于以上分析，生成{max_payloads}个创新的XSS payload，要求:
1. 专门针对检测到的净化器和过滤器设计绕过方法
2. 与已测试的标准payload不同
3. 利用这段PHP代码的特定特征
4. 考虑sink上下文类型（{context_type}）
5. 使用多种绕过技术：大小写变化、编码、双写、注释、协议等
6. payload中必须包含alert(711)或confirm(711)或prompt(711)用于验证
7. **如果检测到strip_tags，必须使用允许的标签并添加事件处理器！**

## 输出格式:
只返回一个JSON数组，包含payload字符串，不要有任何解释：
["payload1", "payload2", "payload3", ...]

注意：payload必须是可以直接使用的字符串，包含完整的XSS攻击向量。
"""
        
        return prompt
    
    def _call_llm_api(self, prompt: str) -> str:
        """调用LLM API"""
        
        if self.provider == 'qwen':
            return self._call_qwen_api(prompt)
        elif self.provider == 'ernie':
            return self._call_ernie_api(prompt)
        elif self.provider == 'zhipu':
            return self._call_zhipu_api(prompt)
        elif self.provider == 'deepseek':
            return self._call_deepseek_api(prompt)
        elif self.provider == 'openai':
            return self._call_openai_api(prompt)
        elif self.provider == 'claude':
            return self._call_claude_api(prompt)
        elif self.provider == 'local':
            return self._call_local_api(prompt)
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")
    
    def _call_qwen_api(self, prompt: str) -> str:
        """调用通义千问API"""
        url = self.api_base or "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation"
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model,
            "input": {
                "messages": [
                    {"role": "system", "content": "你是一个XSS安全测试专家，擅长分析PHP代码并生成绕过净化器的payload。"},
                    {"role": "user", "content": prompt}
                ]
            },
            "parameters": {
                "temperature": 0.7,
                "max_tokens": 2000
            }
        }
        
        try:
            response = requests.post(url, headers=headers, json=data, timeout=60)
            response.raise_for_status()
            result = response.json()
            
            # 通义千问的响应格式: result['output']['text']
            if 'output' in result and 'text' in result['output']:
                return result['output']['text']
            # 备用格式: result['output']['choices'][0]['message']['content']
            elif 'output' in result and 'choices' in result['output']:
                return result['output']['choices'][0]['message']['content']
            else:
                logger.error(f"Unexpected Qwen API response format: {result}")
                raise ValueError(f"Unexpected response format: {result.keys()}")
                
        except Exception as e:
            logger.error(f"Qwen API call failed: {e}")
            raise
    
    def _call_ernie_api(self, prompt: str) -> str:
        """调用文心一言API"""
        # 文心一言需要先获取access_token
        token_url = f"https://aip.baidubce.com/oauth/2.0/token?grant_type=client_credentials&client_id={self.api_key}&client_secret={os.getenv('ERNIE_SECRET_KEY')}"
        
        try:
            token_response = requests.get(token_url, timeout=30)
            token_response.raise_for_status()
            access_token = token_response.json()['access_token']
        except Exception as e:
            logger.error(f"Failed to get ERNIE access token: {e}")
            raise
        
        # 调用文心一言API
        url = f"{self.api_base or 'https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat'}/{self.model}?access_token={access_token}"
        
        data = {
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_output_tokens": 2000
        }
        
        try:
            response = requests.post(url, json=data, timeout=60)
            response.raise_for_status()
            result = response.json()
            return result['result']
        except Exception as e:
            logger.error(f"ERNIE API call failed: {e}")
            raise
    
    def _call_zhipu_api(self, prompt: str) -> str:
        """调用智谱AI API"""
        url = self.api_base or "https://open.bigmodel.cn/api/paas/v4/chat/completions"
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "你是一个XSS安全测试专家，擅长分析PHP代码并生成绕过净化器的payload。"},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": 2000
        }
        
        try:
            response = requests.post(url, headers=headers, json=data, timeout=60)
            response.raise_for_status()
            result = response.json()
            return result['choices'][0]['message']['content']
        except Exception as e:
            logger.error(f"Zhipu API call failed: {e}")
            raise
    
    def _call_deepseek_api(self, prompt: str) -> str:
        """调用DeepSeek API"""
        url = self.api_base or "https://api.deepseek.com/v1/chat/completions"
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are an XSS security testing expert who specializes in analyzing PHP code and generating payloads to bypass sanitizers."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": 2000
        }
        
        try:
            response = requests.post(url, headers=headers, json=data, timeout=60)
            response.raise_for_status()
            result = response.json()
            return result['choices'][0]['message']['content']
        except Exception as e:
            logger.error(f"DeepSeek API call failed: {e}")
            raise
    
    def _call_openai_api(self, prompt: str) -> str:
        """调用OpenAI API"""
        url = self.api_base or "https://api.openai.com/v1/chat/completions"
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are an XSS security testing expert who specializes in analyzing PHP code and generating payloads to bypass sanitizers."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": 2000
        }
        
        try:
            response = requests.post(url, headers=headers, json=data, timeout=60)
            response.raise_for_status()
            result = response.json()
            return result['choices'][0]['message']['content']
        except Exception as e:
            logger.error(f"OpenAI API call failed: {e}")
            raise
    
    def _call_claude_api(self, prompt: str) -> str:
        """调用Claude API"""
        url = self.api_base or "https://api.anthropic.com/v1/messages"
        
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model,
            "max_tokens": 2000,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }
        
        try:
            response = requests.post(url, headers=headers, json=data, timeout=60)
            response.raise_for_status()
            result = response.json()
            return result['content'][0]['text']
        except Exception as e:
            logger.error(f"Claude API call failed: {e}")
            raise
    
    def _call_local_api(self, prompt: str) -> str:
        """调用本地模型API (Ollama/LM Studio)"""
        url = self.api_base or "http://localhost:11434/api/generate"
        
        data = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }
        
        try:
            response = requests.post(url, json=data, timeout=120)
            response.raise_for_status()
            result = response.json()
            return result.get('response', '')
        except Exception as e:
            logger.error(f"Local API call failed: {e}")
            raise
    
    def _parse_llm_output(self, llm_output: str) -> List[str]:
        """
        解析LLM输出，提取payload列表
        支持多种输出格式
        """
        payloads = []
        
        # 策略1: 直接JSON解析
        try:
            payloads = json.loads(llm_output)
            if isinstance(payloads, list):
                return [str(p) for p in payloads if p]
        except:
            pass
        
        # 策略2: 提取JSON数组（可能包含在其他文本中）
        json_match = re.search(r'\[.*?\]', llm_output, re.DOTALL)
        if json_match:
            try:
                payloads = json.loads(json_match.group(0))
                if isinstance(payloads, list):
                    return [str(p) for p in payloads if p]
            except:
                pass
        
        # 策略3: 提取代码块中的JSON
        code_block_match = re.search(r'```(?:json)?\s*(\[.*?\])\s*```', llm_output, re.DOTALL)
        if code_block_match:
            try:
                payloads = json.loads(code_block_match.group(1))
                if isinstance(payloads, list):
                    return [str(p) for p in payloads if p]
            except:
                pass
        
        # 策略4: 逐行解析（后备方案）
        lines = llm_output.strip().split('\n')
        payloads = []
        for line in lines:
            line = line.strip()
            # 移除行首的数字、引号等
            line = re.sub(r'^\d+[\.\)]\s*', '', line)
            line = line.strip('"\'')
            
            # 检查是否看起来像payload
            if '<' in line or 'javascript:' in line or 'alert' in line or 'confirm' in line or 'prompt' in line:
                if len(line) > 5 and len(line) < 500:  # 合理的长度
                    payloads.append(line)
        
        if payloads:
            logger.info(f"Parsed {len(payloads)} payloads using line-by-line strategy")
            return payloads
        
        logger.warning("Failed to parse LLM output, returning empty list")
        return []
    
    def _static_code_analysis(self, php_code: str, function_code: str = "") -> Dict:
        """
        静态分析PHP代码，提取关键信息
        不依赖运行时context
        
        Args:
            php_code: 主PHP代码
            function_code: 函数定义代码
        
        Returns:
            静态分析结果
        """
        full_code = php_code + "\n" + function_code
        
        # 提取输入参数
        input_params = []
        get_params = re.findall(r'\$_GET\[[\"\'](\w+)[\"\']\]', full_code)
        post_params = re.findall(r'\$_POST\[[\"\'](\w+)[\"\']\]', full_code)
        request_params = re.findall(r'\$_REQUEST\[[\"\'](\w+)[\"\']\]', full_code)
        cookie_params = re.findall(r'\$_COOKIE\[[\"\'](\w+)[\"\']\]', full_code)
        server_params = re.findall(r'\$_SERVER\[[\"\'](\w+)[\"\']\]', full_code)
        
        for param in get_params:
            if param not in [p['name'] for p in input_params]:
                input_params.append({'name': param, 'method': 'GET'})
        for param in post_params:
            if param not in [p['name'] for p in input_params]:
                input_params.append({'name': param, 'method': 'POST'})
        for param in request_params:
            if param not in [p['name'] for p in input_params]:
                input_params.append({'name': param, 'method': 'REQUEST'})
        for param in cookie_params:
            if param not in [p['name'] for p in input_params]:
                input_params.append({'name': param, 'method': 'COOKIE'})
        for param in server_params:
            if param not in [p['name'] for p in input_params]:
                input_params.append({'name': param, 'method': 'SERVER'})
        
        # 提取输出点
        output_points = []
        
        # echo语句
        echo_matches = re.finditer(r'echo\s*\(?\s*([^;]+)', full_code, re.IGNORECASE)
        for match in echo_matches:
            output_points.append({
                'type': 'echo',
                'content': match.group(1)[:100]
            })
        
        # die语句
        die_matches = re.finditer(r'die\s*\(([^)]+)\)', full_code, re.IGNORECASE)
        for match in die_matches:
            output_points.append({
                'type': 'die',
                'content': match.group(1)[:100]
            })
        
        # print语句
        print_matches = re.finditer(r'print\s+([^;]+)', full_code, re.IGNORECASE)
        for match in print_matches:
            output_points.append({
                'type': 'print',
                'content': match.group(1)[:100]
            })
        
        # 提取净化器和过滤器
        sanitizers = self._extract_sanitizers(full_code)
        filters = self._extract_filters(full_code)
        encoding_functions = self._extract_encoding_functions(full_code)
        
        # 数据流分析（简化版）
        data_flow = self._simple_data_flow_analysis(full_code, input_params, output_points)
        
        return {
            'input_params': input_params,
            'output_points': output_points,
            'sanitizers': sanitizers,
            'filters': filters,
            'encoding_functions': encoding_functions,
            'data_flow': data_flow,
            'code_patterns': self._extract_code_patterns(full_code)
        }
    
    def _simple_data_flow_analysis(self, code: str, input_params: List[Dict], 
                                   output_points: List[Dict]) -> List[Dict]:
        """
        简化的数据流分析
        追踪从输入到输出的路径
        """
        flows = []
        
        for input_param in input_params:
            param_name = input_param['name']
            method = input_param['method']
            
            # 查找使用该参数的变量赋值
            var_pattern = rf'\$(\w+)\s*=\s*\$_{method}\[["\']' + param_name + r'["\']\]'
            var_matches = re.findall(var_pattern, code)
            
            tracked_vars = [f'$_{method}["{param_name}"]'] + [f'${v}' for v in var_matches]
            
            # 检查这些变量是否出现在输出点
            for output in output_points:
                for var in tracked_vars:
                    if var in output['content']:
                        flows.append({
                            'input': param_name,
                            'input_method': method,
                            'output_type': output['type'],
                            'has_direct_flow': True
                        })
                        break
        
        return flows
    
    def _generate_payloads_from_static_analysis(self, analysis: Dict, 
                                                max_payloads: int = 20) -> List[str]:
        """
        基于静态分析结果，使用LLM生成payload
        
        Args:
            analysis: 静态分析结果
            max_payloads: 最多生成的payload数量
        
        Returns:
            payload列表
        """
        logger.info("[LLM Static] Generating payloads from static analysis...")
        
        # 构建专门的prompt
        prompt = self._build_static_analysis_prompt(analysis, max_payloads)
        
        try:
            # 调用LLM
            llm_output = self._call_llm_api(prompt)
            
            # 解析输出
            payloads = self._parse_llm_output(llm_output)
            
            logger.info(f"[LLM Static] Generated {len(payloads)} payloads")
            return payloads[:max_payloads]
        
        except Exception as e:
            logger.error(f"[LLM Static] Failed to generate payloads: {e}")
            return []
    
    def _build_static_analysis_prompt(self, analysis: Dict, max_payloads: int) -> str:
        """构建静态分析的LLM prompt"""
        
        # 格式化输入参数
        input_params_str = ""
        if analysis['input_params']:
            input_params_str = "输入参数:\n"
            for param in analysis['input_params'][:10]:
                input_params_str += f"- {param['method']}: {param['name']}\n"
        else:
            input_params_str = "未检测到明确的输入参数\n"
        
        # 格式化输出点
        output_points_str = ""
        if analysis['output_points']:
            output_points_str = "输出点:\n"
            for output in analysis['output_points'][:10]:
                output_points_str += f"- {output['type']}: {output['content'][:60]}...\n"
        else:
            output_points_str = "未检测到明确的输出点\n"
        
        # 格式化数据流
        data_flow_str = ""
        if analysis['data_flow']:
            data_flow_str = "数据流分析:\n"
            for flow in analysis['data_flow'][:5]:
                data_flow_str += f"- {flow['input']} ({flow['input_method']}) → {flow['output_type']}\n"
        else:
            data_flow_str = "未检测到明确的数据流\n"
        
        # 格式化净化器
        sanitizers_str = ""
        if analysis['sanitizers']:
            sanitizers_str = "检测到的净化器:\n"
            for san in analysis['sanitizers'][:5]:
                sanitizers_str += f"- {san['function']}({san['params'][:50]}...)\n"
        else:
            sanitizers_str = "未检测到净化器\n"
        
        # 格式化过滤器
        filters_str = ""
        if analysis['filters']:
            filters_str = "检测到的过滤器:\n"
            for flt in analysis['filters'][:5]:
                filters_str += f"- {flt['type']}: {flt['pattern'][:50]}\n"
        else:
            filters_str = "未检测到过滤器\n"
        
        prompt = f"""# XSS Payload生成任务（静态分析模式）

## 背景
这是一个无法通过标准动态测试解析上下文的PHP文件。我们需要基于静态代码分析生成XSS payload。

## 静态分析结果

### {input_params_str}

### {output_points_str}

### {data_flow_str}

### {sanitizers_str}

### {filters_str}

### 编码函数:
{', '.join(analysis['encoding_functions']) if analysis['encoding_functions'] else '无'}

### 代码特征:
- 引号转义: {'是' if analysis['code_patterns']['has_quotes_escape'] else '否'}
- HTML编码: {'是' if analysis['code_patterns']['has_html_encode'] else '否'}
- 标签过滤: {'是' if analysis['code_patterns']['has_tag_strip'] else '否'}
- 正则过滤: {'是' if analysis['code_patterns']['has_regex_filter'] else '否'}
- 字符串替换: {'是' if analysis['code_patterns']['has_string_replace'] else '否'}

## 特殊情况分析

### 如果输出点是die()或exit():
- 这些函数会直接输出内容并终止脚本
- 输出通常是纯文本，没有HTML结构
- 需要生成能在纯文本环境中触发的payload
- 推荐策略：
  1. 如果内容会被浏览器解析为HTML，使用标准XSS payload
  2. 如果是文件内容输出，考虑文件包含漏洞

### 如果没有明确的输入参数:
- 可能使用了变量或其他输入方式
- 尝试常见的参数名：input, data, value, text, content, query, search

### 如果没有明确的输出点:
- 可能输出被隐藏或间接输出
- 仍然生成payload，因为可能存在我们未检测到的输出

## 你的任务:
首先分析该php可能出现的漏洞
根据可能的漏洞，生成{max_payloads}个XSS payload，要求:
1. 针对检测到的净化器和过滤器设计绕过方法
2. 考虑输出点的类型（echo/die/print）
3. 如果有数据流信息，针对性地构造payload
4. 使用多种绕过技术：
   - 大小写变化
   - 编码（HTML实体、URL编码、Unicode）
   - 双写绕过
   - 注释插入
   - 协议变体（javascript:, data:, vbscript:）
   - 事件处理器（onload, onerror, onmouseover等）
5. payload必须包含alert(711)、confirm(711)或prompt(711)
6. 生成多样化的payload，覆盖不同的攻击向量

## 输出格式:
只返回一个JSON数组，包含payload字符串：
["payload1", "payload2", "payload3", ...]

注意：
- payload必须是完整的、可直接使用的XSS攻击向量
- 不要添加任何解释或注释
- 确保JSON格式正确
- 分析该php可能出现的漏洞，根据漏洞，构造对应的payload
"""
        
        return prompt
    

