from .config_model import required_attributes
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import re
import numpy as np
import os

from .config_model import xt_file

def extract_temp_params(string):
    temp_params = re.findall(r"\$_GET\['(temp_\w+)'\]", string)
    return temp_params

def extract_main_param(php_file_path):
    """
    提取 PUT 的 GET 注入入口；优先识别提取器生成的 input 适配赋值。
    """
    try:
        with open(php_file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Generated PUTs overwrite the original source from $_GET['input'],
        # e.g. $_GET['name'] = $_GET['input'] or $_POST['comment'] = ... .
        # Injecting into the assignment target would then lose the payload.
        input_adapter = re.search(
            r"\$\w+(?:\s*\[[^\]\r\n]+\])*\s*=\s*"
            r"\$_GET\s*\[\s*(['\"])input\1\s*\]",
            content,
        )
        if input_adapter:
            return 'input'
        
        # 匹配 $_GET["param_name"] 或 $_GET['param_name']
        params = re.findall(r'\$_GET\[[\"\'](\w+)[\"\']\]', content)
        
        # 过滤掉temp_开头的参数，返回第一个非temp参数
        for param in params:
            if not param.startswith('temp_'):
                return param
        
        # 如果没找到，默认返回'input'
        return 'input'
    except Exception as e:
        print(f"[!] 提取参数名失败: {e}")
        return 'input'

def extract_tags(string):
    tag_names = re.findall(r'<(/?\w+)', string)
    tag_names = [tag.lstrip('/') for tag in tag_names]
    return tag_names

def extract_functions_and_params(test_put_path, target_functions):
    try:
        with open(test_put_path, 'r', encoding='utf-8') as file:
            php_code = file.read()
    except FileNotFoundError:
        print(f"文件未找到: {test_put_path}")
        return None
    except Exception as e:
        print(f"读取文件时发生错误: {e}")
        return None
    finally:
        results = []
        pattern = r'\b(' + '|'.join(target_functions) + r')\s*\(([^)]*)\)'
        matches = re.findall(pattern, php_code)
        for func_name, params in matches:
            params = params.strip()
            results.append({
                "function": func_name,
                "params": params,
            })
        return results

def str_replace_params(function_details):
    search_list = []

    for item in function_details:
        if item['function'] == 'str_replace':
            params = [re.sub(r'[\'"]', '', param.strip()) for param in item['params'].split(',')]
            
            if len(params) > 0:
                search_value = params[0]
                search_list.append(search_value)
    return search_list

def extract_blacklist(function_detail):
    blacklist = []

    for func in function_detail:
        func_name = func["function"]
        params = func["params"]

        if func_name == "str_replace":
            if len(params) > 0:
                first_param = params[0]
                strings = extract_strings_from_param(first_param)
                blacklist.extend(strings)

        elif func_name == "htmlspecialchars":
            if len(params) > 1:
                second_param = params[1]
                if second_param == "ENT_COMPAT":
                    blacklist.extend(["&",">","<","\""])
                elif second_param == "ENT_QUOTES":
                    blacklist.extend(["&",">","<","\"","'"])
                elif second_param == "ENT_HTML5":
                    blacklist.extend(["&",">","<"])
            else:
                blacklist.extend(["&",">","<","\""])
        elif func_name == "htmlentities":
            if len(params) > 1:
                second_param = params[1]
                if second_param == "ENT_COMPAT":
                    blacklist.extend(["&",">","<","\""])
                elif second_param == "ENT_QUOTES":
                    blacklist.extend(["&",">","<","\"","'"])
                elif second_param == "ENT_HTML5":
                    blacklist.extend(["&",">","<"])
            else:
                blacklist.extend(["&",">","<","\""])
    return blacklist

def extract_strings_from_param(param):
    strings = re.findall(r"'([^']*)'", param)
    strings += re.findall(r'"([^"]*)"', param)
    return strings

def calculate_cosine_similarity(str1, str2):
    vectorizer = CountVectorizer().fit([str1, str2])
    vectors = vectorizer.transform([str1, str2])
    similarity = cosine_similarity(vectors[0], vectors[1])
    return similarity[0][0]

def edit_distance(s1, s2):
    m, n = len(s1), len(s2)
    dp = np.zeros((m + 1, n + 1), dtype=int)
    
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
        
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i - 1] == s2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]) + 1
                
    return dp[m][n]

def chose_most_similar(init_vector, new_vectors):
    min_distance = float('inf')
    most_similar_string = None
    
    for new_vector in new_vectors:
        distance = edit_distance(init_vector, new_vector)
        if distance < min_distance:
            min_distance = distance
            most_similar_string = new_vector
    
    return most_similar_string
    
def caculate_similarity(A, B, position):
    len_A, len_B = len(A), len(B)
    if len_A <= position:
        distance = edit_distance(A, B)
        similarity = 1 - distance / max(len_A, len_B)
        return similarity
    
    min_distance = float('inf')
    
    substring = A[position:position + len_B]
    min_distance = edit_distance(substring, B)

    similarity = 1 - min_distance / max(len_A, len_B)
    return similarity

def find_most_similar(response, payload, position):
    return caculate_similarity(response, payload, position) > 0.9


def generate_tag(tag, src, event, filling):
    if tag in required_attributes:
        for attr in required_attributes[tag]:
            if attr not in src:
                src[attr] = f"default_{attr}"

    attributes = {**src, **event}
    attributes_str_double = filling.join(f'{key}="{value}"' for key, value in attributes.items())
    attributes_str_none = filling.join(f'{key}={value}' for key, value in attributes.items())

    if tag.lower() in ["img", "input", "br", "hr", "meta", "link"]:
        double_quote_tag = f"<{tag}{filling}{attributes_str_double}>"
        none_quote_tag = f"<{tag}{filling}{attributes_str_none}>"
    else:
        double_quote_tag = f"<{tag}{filling}{attributes_str_double}>xssky</{tag}>"
        none_quote_tag = f"<{tag}{filling}{attributes_str_none}>xssky</{tag}>"

    return double_quote_tag, none_quote_tag

def read_matched_substring(log_file):
    matched_substrings = []
    with open(log_file, 'r') as log:
        for line in log:
            if "Matched Substring:" in line:
                matched_substring = line.split("Matched Substring:")[1].strip()
                matched_substrings.append(matched_substring)

    with open(log_file, 'w') as log:
        log.truncate(0)

    return matched_substrings

def clear_log_files(folder_path):
    """
    清空日志文件夹中的所有日志文件
    如果目录或文件不存在，自动创建
    """
    # 确保feedback目录存在
    if not os.path.exists(folder_path):
        try:
            os.makedirs(folder_path, mode=0o777, exist_ok=True)
            print(f"[+] 创建feedback目录: {folder_path}")
        except Exception as e:
            print(f"[!] 创建feedback目录失败: {e}")
            return
    
    # 需要的日志文件列表
    required_logs = ['preg_replace.log', 'str_replace.log', 'htmlencode.log', 'strip_tags.log']
    
    # 确保所有必需的日志文件存在
    for log_file in required_logs:
        log_path = os.path.join(folder_path, log_file)
        if not os.path.exists(log_path):
            try:
                with open(log_path, 'w') as f:
                    pass  # 创建空文件
                os.chmod(log_path, 0o666)
                print(f"[+] 创建日志文件: {log_path}")
            except Exception as e:
                print(f"[!] 创建日志文件失败 {log_path}: {e}")
    
    # 清空所有日志文件
    for file_name in os.listdir(folder_path):
        if file_name.endswith('.log'):
            file_path = os.path.join(folder_path, file_name)
            try:
                with open(file_path, 'w') as file:
                    file.truncate(0)
            except Exception as e:
                print(f"[!] 清空日志文件失败 {file_path}: {e}")

def parse_logs(log_folder, vector):
    """
    解析日志文件夹中的所有日志文件
    如果目录或文件不存在，自动创建
    """
    results = {}
    
    # 确保feedback目录存在
    if not os.path.exists(log_folder):
        try:
            os.makedirs(log_folder, mode=0o777, exist_ok=True)
            print(f"[+] 创建feedback目录: {log_folder}")
        except Exception as e:
            print(f"[!] 创建feedback目录失败: {e}")
            return results
    
    # 需要的日志文件列表
    required_logs = ['preg_replace.log', 'str_replace.log', 'htmlencode.log', 'strip_tags.log']
    
    # 确保所有必需的日志文件存在
    for log_file in required_logs:
        log_path = os.path.join(log_folder, log_file)
        if not os.path.exists(log_path):
            try:
                with open(log_path, 'w') as f:
                    pass  # 创建空文件
                os.chmod(log_path, 0o666)
                print(f"[+] 创建日志文件: {log_path}")
            except Exception as e:
                print(f"[!] 创建日志文件失败 {log_path}: {e}")

    for log_file in os.listdir(log_folder):
        if not log_file.endswith('.log'):
            continue
            
        file_path = os.path.join(log_folder, log_file)
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
        except Exception as e:
            print(f"[!] 读取日志文件失败 {file_path}: {e}")
            results[log_file] = {"Message": f"Error reading file: {e}"}
            continue

        if log_file == 'htmlencode.log':
            input_matches = re.findall(r'Input string:\s*["\']?(.*?)["\']?\n', content)
            matched_matches = re.findall(r'Quotes:\s*(\w+)', content)

            matches = []
            for i in range(len(input_matches)):
                if (1 - (edit_distance(vector, input_matches[i])/max(len(vector), len(input_matches[i])))) > 0.5:
                    matches.append({"Input String": input_matches[i], "Quotes": matched_matches[i]})
            results[log_file] = matches

        elif log_file == 'preg_replace.log':
            input_matches = re.findall(r'Original String:\s*(.*?)\n', content)
            matched_matches = re.findall(r'Matched Substring:\s*(.*?)\n', content)

            matches = []
            for i in range(len(input_matches)):
                if (1 - (edit_distance(vector, input_matches[i])/max(len(vector), len(input_matches[i])))) > 0.5:
                    matches.append({"Input String": input_matches[i], "Matched Substring": matched_matches[i]})
            results[log_file] = matches

        elif log_file == 'strip_tags.log':
            input_matches = re.findall(r'Input Strings:(.*)', content)
            matched_matches = re.findall(r'Allow Tags:(.*)', content)

            matches = []
            for i in range(len(input_matches)):
                if (1 - (edit_distance(vector, input_matches[i])/max(len(vector), len(input_matches[i])))) > 0.5:
                    matches.append({"Input String": input_matches[i], "Allow Tags": matched_matches[i]})
            results[log_file] = matches
        
        elif log_file == 'str_replace.log':
            input_matches = re.findall(r'Subject:\s*(.*?)\n', content)
            matched_matches = re.findall(r'Search:\s*(.*?)\n', content)

            matches = []
            for i in range(len(input_matches)):
                if (1 - (edit_distance(vector, input_matches[i])/max(len(vector), len(input_matches[i])))) > 0.5:
                    matches.append({"Input String": input_matches[i], "Search String": matched_matches[i]})
            results[log_file] = matches
        else:
            results[log_file] = {"Message": "Unsupported log format"}

        with open(file_path, 'w') as file:
            file.truncate(0)

    return results

def htmlencode_mode(terminator, feedback_message):
    if terminator == '"':
        for entry in feedback_message['htmlencode.log']:
            if 'Quotes' in entry and entry['Quotes'] is not None and (entry['Quotes'] == "DOUBLE" or entry['Quotes'] == "SINGLE"):
                return False
    if terminator == "'":
        for entry in feedback_message['htmlencode.log']:
            if 'Quotes' in entry and entry['Quotes'] is not None and entry['Quotes'] == "SINGLE":
                return False
    return True
    
def input_similarity(feedback_message, vector):
    if 'preg_replace.log' in feedback_message:
        for entry in feedback_message['preg_replace.log']:
            if ('Input String' in entry and 
                entry['Input String'] is not None and 
                ((1 - edit_distance(vector, entry['Input String'])) > 0.5)):
                return True

    if 'str_replace.log' in feedback_message:
        for entry in feedback_message['str_replace.log']:
            if ('Input String' in entry and 
                entry['Input String'] is not None and 
                ((1 - edit_distance(vector, entry['Input String'])) > 0.5)):
                return True
            
def get_matched_string(feedback_message):
    matched_substrings = []

    if 'preg_replace.log' in feedback_message:
        for entry in feedback_message['preg_replace.log']:
            if 'Matched Substring' in entry:
                if isinstance(entry['Matched Substring'], str):
                    matched_substrings.append(entry['Matched Substring'])
                elif isinstance(entry['Matched Substring'], list):
                    matched_substrings.extend(entry['Matched Substring'])

    if 'str_replace.log' in feedback_message:
        for entry in feedback_message['str_replace.log']:
            if 'Search String' in entry:
                if isinstance(entry['Search String'], str):
                    matched_substrings.append(entry['Search String'])
                elif isinstance(entry['Search String'], list):
                    matched_substrings.extend(entry['Search String'])
    return matched_substrings
    
def parse_xt_file(file_path):
    """
    解析反馈日志文件，提取函数调用信息
    如果目录或文件不存在，自动创建
    """
    function_calls = {}
    
    # 确保feedback目录存在
    if not os.path.exists(file_path):
        try:
            os.makedirs(file_path, mode=0o777, exist_ok=True)
            print(f"[+] 创建feedback目录: {file_path}")
        except Exception as e:
            print(f"[!] 创建feedback目录失败: {e}")
            return function_calls
    
    # 需要的日志文件列表
    required_logs = ['preg_replace.log', 'str_replace.log', 'htmlencode.log', 'strip_tags.log']
    
    # 确保所有必需的日志文件存在
    for log_file in required_logs:
        log_path = os.path.join(file_path, log_file)
        if not os.path.exists(log_path):
            try:
                with open(log_path, 'w') as f:
                    pass  # 创建空文件
                os.chmod(log_path, 0o666)
                print(f"[+] 创建日志文件: {log_path}")
            except Exception as e:
                print(f"[!] 创建日志文件失败 {log_path}: {e}")
    
    # 解析preg_replace.log
    preg_replace_path = os.path.join(file_path, 'preg_replace.log')
    try:
        with open(preg_replace_path, 'r') as file:
            content = file.read()
            function_name = "preg_replace"
            line_numbers = re.findall(r'Function Called lineno:\s*(.*?)\n', content)
            params_list = re.findall(r'Original String:\s*(.*?)\n', content)
            
            # 配对每个line_number和对应的params
            for i in range(min(len(line_numbers), len(params_list))):
                line_num = line_numbers[i] if i < len(line_numbers) else "unknown"
                param = params_list[i] if i < len(params_list) else ""
                key = (function_name, line_num)
                if key not in function_calls:
                    function_calls[key] = []
                function_calls[key].append((param,))
    except Exception as e:
        print(f"[!] 读取preg_replace.log失败: {e}")

    # 解析str_replace.log
    str_replace_path = os.path.join(file_path, 'str_replace.log')
    try:
        with open(str_replace_path, 'r') as file:
            content = file.read()
            function_name = "str_replace"
            line_numbers = re.findall(r'Function Called lineno:\s*(.*?)\n', content)
            params_list = re.findall(r'Subject:\s*(.*?)\n', content)
            
            # 配对每个line_number和对应的params
            for i in range(min(len(line_numbers), len(params_list))):
                line_num = line_numbers[i] if i < len(line_numbers) else "unknown"
                param = params_list[i] if i < len(params_list) else ""
                key = (function_name, line_num)
                if key not in function_calls:
                    function_calls[key] = []
                function_calls[key].append((param,))
    except Exception as e:
        print(f"[!] 读取str_replace.log失败: {e}")

    return function_calls

def compare_function_calls(pre_function_calls, post_function_calls):
    # 如果没有前置调用记录，无法进行有意义的比较，返回 False（不触发验证）
    if not pre_function_calls:
        return False
    for key, calls in pre_function_calls.items():
        function_name , line_number = key
        calls_set1 = set(calls)
        calls_set2 = set(post_function_calls.get(key,[]))
        if len(post_function_calls.get(key, [])) > len(calls):
            return False
        else:
            continue
    return True