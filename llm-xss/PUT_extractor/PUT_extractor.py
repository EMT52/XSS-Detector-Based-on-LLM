import json
import os
import time
import traceback
import signal
import sys, getopt
import shutil
from typing import Union, List, Tuple
from datetime import datetime
import numpy as np
import pandas as pd
import py2neo
import re
import logging
import time

from config import DATABASE_PATH, STORAGE_PATH
from core.ast2code import Ast2CodeFactory
from core.neo4j_connector_center import Neo4jConnectorCenter
from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *
from core.function_extractor import FunctionExtractor
from core.sink_context_analyzer import sink_context_analysis
from core.undefined_symbol_handler import UndefinedSymbolHandler

DATABASE_PATH = './databases'
PUT_STORAGE_PATH = os.path.join(STORAGE_PATH, 'PUT')
TAINT_FLOW_STORAGE_PATH = os.path.join(STORAGE_PATH, 'taint_flows')
logger = logging.getLogger(__name__)


def fix_php_syntax(php_code):
    """Apply legacy placeholder cleanup without rewriting echo expressions.

    String literals are escaped by SymbolicTracking. Rewriting an entire echo
    with a regex also escapes the quotes delimiting valid concatenation operands
    and changes the HTML context. The preparation entry point validates syntax
    with php -l instead of guessing where a string should end.
    """
    # 2. 智能替换 placeholder 变量
    # 尝试从上下文中推断正确的变量名
    # 查找最近的赋值语句，使用被赋值的变量
    lines = php_code.split('\n')
    last_assigned_var = None
    fixed_lines = []
    
    for line in lines:
        # 查找赋值语句: $var = ...
        assign_match = re.search(r'\$(\w+)\s*=', line)
        if assign_match and not line.strip().startswith('//'):
            var_name = assign_match.group(1)
            # 排除临时变量和 $_GET/$_POST
            if not var_name.startswith('_') and var_name not in ['GET', 'POST', 'REQUEST', 'COOKIE', 'SESSION']:
                last_assigned_var = var_name
        
        # 替换 placeholder
        if '$' in line and '_placeholder' in line:
            if last_assigned_var:
                # 使用最近赋值的变量替换 placeholder
                line = re.sub(r'\$\w+_placeholder', f'${last_assigned_var}', line)
            else:
                # 如果找不到变量，替换为空字符串
                line = re.sub(r'\$\w+_placeholder', '""', line)
        
        fixed_lines.append(line)
    
    php_code = '\n'.join(fixed_lines)
    
    # 3. 移除单独的 null; 语句
    php_code = re.sub(r'^\s*null;\s*$', '', php_code, flags=re.MULTILINE)
    
    # 4. 修复 isset(intval(...)) 语法错误
    # PHP 中 isset() 只能用于变量，不能用于函数返回值
    # 原始代码: isset($_REQUEST["x"]) ? intval($_REQUEST["x"]) : 0
    # 错误生成: isset(intval($_REQUEST["x"])) ? intval($_REQUEST["x"]) : 0
    # 修复为:   isset($_REQUEST["x"]) ? intval($_REQUEST["x"]) : 0
    php_code = re.sub(
        r'isset\(intval\(([^)]+)\)\)',
        r'isset(\1)',
        php_code
    )
    
    # 5. 清理多余的空行
    php_code = re.sub(r'\n\n\n+', '\n\n', php_code)
    
    return php_code


def start_databases(*args) -> int:
    for arg in args:
        if not os.path.exists(f"{DATABASE_PATH}/{arg}/bin/neo4j"):
            logger.info(f"[-] {arg}: Database not built") 
            return 0b00

        io = os.popen(f"{DATABASE_PATH}/{arg}/bin/neo4j status").read()
        if "Neo4j is running" in io:
            logger.info(f"[+] {arg}: Database is running")
            return 0b01

        logger.info(f"Starting database for {arg}...")
        io = os.popen(f"{DATABASE_PATH}/{arg}/bin/neo4j start").read()
        time.sleep(10)
        io = os.popen(
            f"tail -n 10 {DATABASE_PATH}/{arg}/logs/neo4j.log"
        ).read()
        print(io, flush=True)
    return 0b10

def stop_databases(*args):
    for arg in args:
        io = os.popen(f"{DATABASE_PATH}/{arg}/bin/neo4j stop").read()
        if os.path.exists(f"{DATABASE_PATH}/{arg}/run/neo4j.pid"):
            os.remove(f"{DATABASE_PATH}/{arg}/run/neo4j.pid")

def store_json(result: List[dict], base_dir: str, filename: str):
    if not os.path.exists(base_dir):
        os.mkdir(base_dir)
    path = os.path.join(base_dir, filename)
    with open(path, "w") as f:
        json.dump(fp=f, obj=result, indent=2)
        f.flush()
    
def load_taint_flow(target):
    taint_flow_file = os.path.join(TAINT_FLOW_STORAGE_PATH, f"{target}.json")
    assert os.path.exists(taint_flow_file), \
        f"No static reports found, please place the static reports in storage/taint_flows/{target}.json"
    with open(taint_flow_file) as f:
        taint_flows = json.load(f)
    return taint_flows

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "", ["target="])
    except getopt.GetoptError:
        print("Usage: python PUT_extractor.py [--target=xx]")
        sys.exit(1)
    
    # 解析 target 参数
    target = None
    for opt, arg in opts:
        if opt == "--target":
            target = arg
    
    if target is None:
        print("Error: --target parameter is required")
        print("Usage: python PUT_extractor.py --target=test-app")
        sys.exit(1)
    
    database_wait_time = 30
    
    flag = start_databases(target)
    if not flag:
        return

    try:
        logger.info(f"Waiting for {database_wait_time}s to make sure neo4j opened...") 
        time.sleep(database_wait_time)

        logger.info(f"[*] Extracting PUTs for {target}")
        run(target)
        logger.info(f"[+] Finished PUT extracting")
    except:
        logger.info(f"[-] Failed to extract PUTs for {target}")
        print(traceback.format_exc(), flush=True)
        return
    finally:
        stop_databases(target)
        print("", flush=True)

def run(target):
    analyzer_target = Neo4jEngine.from_dict(
        Neo4jConnectorCenter.from_map(target)
    )

    for idx, taint_flow in enumerate(load_taint_flow(target), 1):
        if len(taint_flow) <= 0:
            continue

        path_id = str(idx)  # 使用索引作为路径 ID
        
        # 输出当前处理的污点流信息
        logger.info(f"Processing taint flow #{idx}: {taint_flow}")
        
        # 获取 sink 节点
        sink_node_id = taint_flow[-1]
        logger.info(f"Querying sink node with ID: {sink_node_id}")
        
        try:
            potential_sink = analyzer_target.get_node_itself(sink_node_id)
        except ValueError as e:
            logger.error(f"Failed to get sink node {sink_node_id} for taint flow #{idx}")
            logger.error(f"Taint flow: {taint_flow}")
            raise
        
        # 将列表包装成字典格式供 extract_call_sites 使用
        taint_flow_dict = {'taint_flow': taint_flow}
        
        import time as _time
        _t0 = _time.time()
        logger.info(f"  [DEBUG] Step: extract_call_sites...")
        call_site_series = extract_call_sites(target, analyzer_target, potential_sink, taint_flow_dict)
        logger.info(f"  [DEBUG] extract_call_sites done in {_time.time()-_t0:.1f}s, found {len(call_site_series) if call_site_series else 0} call sites")
        
        # 安全检查：如果 call_site_series 为 None，使用空列表
        if call_site_series is None:
            logger.warning(f"extract_call_sites returned None for path {path_id}, using empty list")
            call_site_series = []
        
        _t0 = _time.time()
        logger.info(f"  [DEBUG] Step: FunctionExtractor.run()...")
        function_extractor = FunctionExtractor(target=target, analyzer=analyzer_target, 
                                                path_id=path_id, call_site_series=call_site_series)
        function_extractor.run()
        logger.info(f"  [DEBUG] FunctionExtractor done in {_time.time()-_t0:.1f}s")

        # 构建 PHP 代码（不包含 <?php ?> 标签）
        path_code = ""
        
        # 1. 添加 source 变量定义（不再在这里放 include，后面再加）
        _t0 = _time.time()
        logger.info(f"  [DEBUG] Step: find_sources...")
        source_node = analyzer_target.get_node_itself(taint_flow[0])
        for source_var in analyzer_target.ast_step.find_sources(source_node):
            path_code += f"{source_var} = $_GET['input'];\n"
        logger.info(f"  [DEBUG] find_sources done in {_time.time()-_t0:.1f}s")
        
        # 2. 过滤污点流节点：只保留全局作用域的节点（funcid 与 source 节点相同）
        # 函数内部的节点（funcid 不同）应该由 function_definition.php 处理
        source_funcid = source_node.get(NODE_FUNCID)
        global_scope_nodes = []
        for node_id in taint_flow[:-1]:
            node = analyzer_target.get_node_itself(node_id)
            if node.get(NODE_FUNCID) == source_funcid:
                global_scope_nodes.append(node_id)
        logger.info(f"  [DEBUG] Global scope nodes: {len(global_scope_nodes)}/{len(taint_flow)-1}")
        
        # 3. 添加路径代码（只提取全局作用域节点，排除函数内部节点）
        _t0 = _time.time()
        logger.info(f"  [DEBUG] Step: extract_code for path...")
        code_list = Ast2CodeFactory.extract_code(analyzer_target, global_scope_nodes) if global_scope_nodes else []
        logger.info(f"  [DEBUG] extract_code(path) done in {_time.time()-_t0:.1f}s")
        if isinstance(code_list, list):
            for code in code_list:
                if code and code.strip():
                    path_code += code + ";\n"
        elif code_list:
            path_code += code_list + ";\n"
        
        # 4. 添加 sink 代码（完整提取，包括子节点）
        _t0 = _time.time()
        logger.info(f"  [DEBUG] Step: extract_code for sink...")
        sink_code = Ast2CodeFactory.extract_code(analyzer_target, potential_sink)
        logger.info(f"  [DEBUG] extract_code(sink) done in {_time.time()-_t0:.1f}s")
        if sink_code and sink_code.strip():
            path_code += sink_code + ";\n"
        
        # 4.5 确保有输出点：如果 sink 不是 echo/print/printf/header 类型，
        # 则自动添加 echo 语句，使 fuzzer 能观测到 XSS payload 的反射
        sink_type = potential_sink.get(NODE_TYPE)
        sink_is_output = sink_type in {TYPE_ECHO, TYPE_PRINT}
        # 检查 sink 是否是 printf/header 等函数调用（也算输出）
        if not sink_is_output and sink_type == TYPE_CALL:
            try:
                call_name = analyzer_target.code_step.get_ast_call_code(potential_sink)
                if call_name in {'printf', 'header', 'wp_die', 'die', 'exit', 'vprintf'}:
                    sink_is_output = True
            except Exception:
                pass
        
        if not sink_is_output and sink_code and sink_code.strip():
            # sink 不是输出语句，需要添加 echo 使结果可观测
            # 从 sink_code 中提取被赋值的变量名
            echo_var = None
            # 模式1: $var=... 或 $var[...]=...
            assign_match = re.match(r'^\s*(\$[\w\[\]"\']+)\s*[.!]?=', sink_code.strip())
            if assign_match:
                echo_var = assign_match.group(1)
            else:
                # 模式2: sprintf/函数调用赋值，如 $t_123=sprintf(...)
                assign_match2 = re.match(r'^\s*(\$\w+)\s*=', sink_code.strip())
                if assign_match2:
                    echo_var = assign_match2.group(1)
            
            if echo_var:
                # 清理变量名中可能的数组索引（如 $messages[] 改为 $messages[0]）
                if echo_var.endswith('[]'):
                    echo_var = echo_var[:-2] + '[0]'
                path_code += f"echo({echo_var});\n"
                logger.info(f"  [DEBUG] Added echo for non-output sink: echo({echo_var})")
            else:
                # 无法提取变量名，尝试用 sink_code 本身作为表达式输出
                # 去掉末尾分号
                sink_expr = sink_code.strip().rstrip(';').strip()
                # 如果是赋值表达式，取右侧
                if '=' in sink_expr and not sink_expr.startswith('$_'):
                    parts = sink_expr.split('=', 1)
                    if len(parts) == 2:
                        sink_expr = parts[1].strip()
                path_code += f"echo({sink_expr});\n"
                logger.info(f"  [DEBUG] Added echo for non-output sink (expr): echo({sink_expr})")
        
        # 5. 跳过 UndefinedSymbolHandler（已通过 funcid 过滤 + stub 机制替代）
        # 它的 temp 赋值全部会被清理掉，且内部 Cypher 查询耗时，无实际意义
        
        # 5.5 对象方法链的正则简化（原 UndefinedSymbolHandler.run() 中的纯正则部分）
        path_code = re.sub(r'(\$?[\w\[\'"\]\(\)]+->)+(\w+\s*\()', r'\2', path_code)
        path_code = re.sub(r'(\$?[\w\[\'"\]\(\)]+->)+([\w\[\'"\]]+)', r'$\2', path_code)
        path_code = re.sub(r'([\$?\w\[\'"\]\(\)]+::)+(\w+\s*\()', r'\2', path_code)
        path_code = re.sub(r'(\\\w+)+\\', '', path_code)
        path_code = re.sub(r'\$this([^\w])', r'$this\1', path_code)
        
        # 6. 在最前面插入 include（确保 include 之前没有其他代码）
        path_code = "include 'function_definition.php';\n\n" + path_code
        
        # 7. 添加 PHP 标签
        path_code = "<?php\n" + path_code + "?>\n"
        
        # 7. 添加 HTML 上下文（如果有）
        predecessor_context, successor_context = sink_context_analysis(analyzer_target, potential_sink)
        if predecessor_context:
            path_code = predecessor_context + path_code
        if successor_context:
            path_code = path_code + successor_context
        
        # 8. 后处理：修复 PHP 语法错误
        path_code = fix_php_syntax(path_code)
        
        os.makedirs(os.path.join(PUT_STORAGE_PATH, target, path_id), exist_ok=True)
        with open(os.path.join(PUT_STORAGE_PATH, target, path_id, "index.php"), "w") as f:
            f.write(path_code)
            f.flush()

def extract_call_sites(target, analyzer_target: Neo4jEngine, potential_sink: py2neo.Node, taint_flow):
    call_site_series = []
    for node_id in taint_flow['taint_flow']:
        node = analyzer_target.get_node_itself(node_id)

        if node[NODE_TYPE] in {TYPE_FOREACH}:
            node = analyzer_target.ast_step.get_ith_child_node(node, 0)

        for call_node in analyzer_target.filter_ast_child_nodes(node, 
                                node_type_filter={TYPE_CALL, TYPE_METHOD_CALL, TYPE_STATIC_CALL}):
            if call_node[NODE_INDEX] not in call_site_series:
                call_site_series.append(call_node[NODE_INDEX])
            else:
                continue
            
            decl_nodes = analyzer_target.cg_step.find_decl_nodes(call_node)
            decl_nodes.extend(analyzer_target.cg_step.match_decl_nodes(call_node))
            if not decl_nodes:
                # 找不到函数声明，继续处理其他节点，而不是返回 None
                logger.warning(f"No declaration found for call node {call_node[NODE_INDEX]}")
                continue

    call_site_series = sorted(call_site_series)
    return call_site_series

if __name__ == "__main__":
    main()
