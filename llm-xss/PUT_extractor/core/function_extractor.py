import os, json
import logging
import py2neo
import re

logger = logging.getLogger(__name__)
from collections import OrderedDict
from typing import Union, List, Tuple

from config import STORAGE_PATH, NONLOCAL_FUNCTIONS
from core.neo4j_engine import Neo4jEngine
from core.model import PHP_BUILT_IN_FUNCTIONS
from core.neo4j_engine.const import *
from core.helper import generate_temporary_var

class FunctionExtractor(object):
    def __init__(self, target: str, analyzer: Neo4jEngine, path_id: int, call_site_series: List[int]):
        self.analyzer = analyzer
        self.target = target
        self.call_site_series = call_site_series
        self.path_id = path_id
        self.__compile_storage_path()

    def __compile_storage_path(self):
        def_storage_basedir = os.path.join(STORAGE_PATH, 'PUT')
        self.def_storage_path = os.path.join(def_storage_basedir, self.target, self.path_id)
        os.makedirs(self.def_storage_path, exist_ok=True)

    def cat_lines_from_file(self, file_path, line_numbers: Union[List, Tuple]) -> List[str]:
        if isinstance(line_numbers, tuple):
            lineno_list = list(range(line_numbers[0], line_numbers[1] + 1))
        else:
            lineno_list = line_numbers
        lineno_set = set(lineno_list)
        selected_lines = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                for lineno, line in enumerate(file, start=1):
                    if lineno in lineno_set:
                        selected_lines.append(line.rstrip())
            return selected_lines
        except (UnicodeDecodeError, FileNotFoundError, OSError):
            return []

    def handle_undefined_dims(self, dep_node: py2neo.Node, dep_code: str) -> str:
        dim_nodes = self.analyzer.filter_ast_child_nodes(dep_node, node_type_filter=[TYPE_DIM])

        dim_body_codes = [self.analyzer.code_step.get_ast_dim_body_code(dim_node)[1:] for dim_node in dim_nodes]
        query = "MATCH (A:AST) - [:PARENT_OF] -> (P) - [:PARENT_OF*0..] -> (V) - [:PARENT_OF] -> (S) " \
                "WHERE A.type='AST_ASSIGN' AND P.childnum=0 AND V.type='AST_VAR' AND S.type='string' " \
                f"AND S.code IN {dim_body_codes.__str__()} RETURN V"
        potential_defined_nodes = [node for node, in self.analyzer.basic_step.run(query)]
        defined_dim_body_codes = []
        defined_dim_codes = []
        for potential_defined_node in potential_defined_nodes:
            parent_node = self.analyzer.ast_step.get_parent_node(potential_defined_node)
            if parent_node is not None and parent_node[NODE_TYPE] == TYPE_DIM:
                defined_dim_codes.append(self.analyzer.code_step.get_ast_dim_code(parent_node))
            else:
                defined_dim_body_codes.append(self.analyzer.code_step.get_ast_var_code(potential_defined_node))
        
        param_nodes = self.analyzer.ast_step.find_function_param_node_list(dep_node)
        param_codes = [self.analyzer.code_step.get_node_code(param_node) for param_node in param_nodes]

        undefined_dim_codes = []
        for dim_node in dim_nodes:
            dim_body_code = self.analyzer.code_step.get_ast_dim_body_code(dim_node)
            if 'NOT_SUPPORT_FOR' in dim_body_code:
                continue
            if dim_body_code in defined_dim_body_codes:
                continue
            if dim_body_code in param_codes:
                continue

            dim_code = self.analyzer.code_step.get_ast_dim_code(dim_node)
            if dim_code in defined_dim_codes:
                continue

            undefined_dim_codes.append(dim_code)
        undefined_dim_codes = list(OrderedDict.fromkeys(undefined_dim_codes))
        undefined_dim_codes = [code if code.startswith('$') else f"${code}" for code in undefined_dim_codes]
        code_to_insert = "\n".join([f"{v} = {generate_temporary_var()};" for v in undefined_dim_codes])
        if code_to_insert:
            code_to_insert += "\n"
        pattern = r'^function\s+\w+\s*\([^\)]*\)\s*\{\s*'
        dep_code = re.sub(pattern, lambda match: match.group(0) + code_to_insert, dep_code)
        return dep_code

    def handle_undefined_vars(self, dep_node: py2neo.Node, dep_code: str) -> str:
        var_nodes = self.analyzer.filter_ast_child_nodes(dep_node, node_type_filter=[TYPE_VAR])
        
        normal_vars = [self.analyzer.code_step.get_ast_var_code(var_node)[1:] for var_node in var_nodes]
        query = "MATCH (A:AST) - [:PARENT_OF] -> (P) - [:PARENT_OF*0..] -> (V) - [:PARENT_OF] -> (S) " \
                "WHERE A.type='AST_ASSIGN' AND P.childnum=0 AND V.type='AST_VAR' AND S.type='string' " \
                f"AND S.code IN {normal_vars.__str__()} RETURN V"
        defined_vars = [self.analyzer.code_step.get_ast_var_code(n) 
                            for n, in self.analyzer.basic_step.run(query)]
        
        param_nodes = self.analyzer.ast_step.find_function_param_node_list(dep_node)
        param_codes = [self.analyzer.code_step.get_node_code(param_node) for param_node in param_nodes]
        
        undefined_vars = []
        for var_node in var_nodes:
            var_code = self.analyzer.code_step.get_node_code(var_node)
            if var_code in defined_vars:
                continue
            if var_code in param_codes:
                continue

            parent_node = self.analyzer.ast_step.get_parent_node(var_node)
            if parent_node[NODE_TYPE] == TYPE_DIM:
                continue

            if parent_node[NODE_TYPE] == TYPE_PROP:
                undefined_vars.append(self.analyzer.code_step.get_node_code(parent_node))
            elif var_code != "$this":
                undefined_vars.append(var_code)

        undefined_vars = list(OrderedDict.fromkeys(undefined_vars))
        code_to_insert = "\n".join([f"{v} = {generate_temporary_var()};" for v in undefined_vars])
        if code_to_insert:
            code_to_insert += "\n"
            code_to_insert = f"global {generate_temporary_var()};\n" + code_to_insert
        pattern = r'^function\s+\w+\s*\([^\)]*\)\s*\{\s*'
        dep_code = re.sub(pattern, lambda match: match.group(0) + code_to_insert, dep_code)
        return dep_code

    def handle_nonlocal_functions(self, dep_code: str) -> str:
        def replace_callback(match: re.Match):
            if match.group(1) is not None:
                return match.group(0)
            full_text = match.group(0)
            parenthesis_stack = []
            for index in range(len(full_text)):
                char = full_text[index]
                if char == '(':
                    parenthesis_stack.append(char)
                elif char == ')':
                    parenthesis_stack = parenthesis_stack[:-1]
                    if len(parenthesis_stack) == 0:
                        return f'{generate_temporary_var()}{full_text[index+1:]}'
        
        re_pattern = fr'(function\s+\w*)?@?({"|".join(NONLOCAL_FUNCTIONS)})\s*\([^;{"{"}]+'
        dep_code = re.sub(re_pattern, replace_callback, dep_code)
        return dep_code
    
    def match_decl_nodes(self, call_node: py2neo.Node):
        if call_node[NODE_TYPE] == TYPE_CALL:
            function_name = self.analyzer.code_step.get_ast_call_code(call_node)
            decl_node_type = [TYPE_FUNC_DECL]
        else:
            function_name = self.analyzer.ast_step.get_ith_child_node(call_node, 1)[NODE_CODE]
            decl_node_type = [TYPE_METHOD]
        arg_node_count = self.analyzer.ast_step.get_function_arg_node_cnt(call_node)
        matched_decl_nodes = [n for n, in self.analyzer.basic_step.run(
            f"MATCH (N:AST) - [:PARENT_OF] -> (M) WHERE N.type in {decl_node_type.__str__()} "
            f"AND M.childnum=0 AND M.code='{function_name}' RETURN N"
        )]
        matched_decl_nodes = [n for n in matched_decl_nodes 
                            if self.analyzer.ast_step.find_function_param_node_list(n).
                            __len__() == arg_node_count]
        return matched_decl_nodes

    def collect_dep_nodes(self, initial_node):
        all_dep_nodes = []
        current_dep_nodes = [initial_node]
        depth = 0
        max_depth = 1  # 只提取函数本身，内部依赖由 stub 覆盖
        # 缓存：同一个 call node 的声明查找结果只查一次
        if not hasattr(self, '_decl_cache'):
            self._decl_cache = {}
        while current_dep_nodes.__len__() > 0 and depth < max_depth:
            depth += 1
            next_dep_nodes = []
            logger.info(f"    [collect_dep_nodes] depth={depth}, processing {len(current_dep_nodes)} nodes, total collected={len(all_dep_nodes)}")
            for dep_node in current_dep_nodes:
                dep_file = self.analyzer.fig_step.get_belong_file(dep_node)
                if "PHPJOERN_PREDEFINE.php" in dep_file:
                    continue

                all_dep_nodes.append(dep_node)
                call_nodes = self.analyzer.filter_ast_child_nodes(dep_node, 
                            node_type_filter={TYPE_CALL, TYPE_METHOD_CALL, TYPE_STATIC_CALL})
                
                for call_node in call_nodes:
                    call_id = call_node[NODE_INDEX]
                    # 用缓存避免重复查询
                    if call_id in self._decl_cache:
                        decl_nodes = self._decl_cache[call_id]
                    else:
                        code = self.analyzer.code_step.get_node_code(call_node)
                        if code in PHP_BUILT_IN_FUNCTIONS and call_node[NODE_TYPE] == TYPE_CALL:
                            self._decl_cache[call_id] = []
                            continue
                        decl_nodes = self.analyzer.cg_step.find_decl_nodes(call_node)
                        if not decl_nodes:
                            decl_nodes = self.analyzer.cg_step.match_decl_nodes(call_node)
                        self._decl_cache[call_id] = decl_nodes
                    if decl_nodes:
                        next_dep_nodes.extend(decl_nodes)
            current_dep_nodes = next_dep_nodes
            current_dep_nodes = [n for n in current_dep_nodes if n not in all_dep_nodes]
            current_dep_nodes = list(OrderedDict((node[NODE_INDEX], node) for node in current_dep_nodes).values())
            logger.info(f"    [collect_dep_nodes] depth={depth} done, next level has {len(current_dep_nodes)} new nodes")
        logger.info(f"    [collect_dep_nodes] finished, total dep nodes: {len(all_dep_nodes)}")
        return all_dep_nodes

    def handle_global_defs(self, dep_node, dep_code):
        global_def_nodes = []
        global_nodes = self.analyzer.filter_ast_child_nodes(dep_node, node_type_filter=[TYPE_GLOBAL])
        const_nodes = self.analyzer.filter_ast_child_nodes(dep_node, node_type_filter=[TYPE_CONST])
        global_vars = []
        for global_node in global_nodes:
            global_vars.extend(self.analyzer.code_step.find_variables(global_node, [TYPE_VAR]))
        global_vars = [v[1:] for v in global_vars]
        global_vars = list(set(global_vars))
        query = "MATCH (A:AST) - [:PARENT_OF] -> (P) - [:PARENT_OF*0..] -> (V) - [:PARENT_OF] -> (S) " \
                "WHERE A.type='AST_ASSIGN' AND P.childnum=0 AND V.type='AST_VAR' AND S.type='string' " \
                f"AND S.code IN {global_vars.__str__()} RETURN A"
        global_def_nodes.extend([node for node, in self.analyzer.basic_step.run(query)])
        consts = [self.analyzer.code_step.get_node_code(const_node) for const_node in const_nodes]
        consts = [c for c in consts if c not in {"null","true","false"}]
        consts = list(set(consts))
        query = "MATCH (C:AST) - [:PARENT_OF] -> (N) - [:PARENT_OF] -> (S) "\
                "MATCH (C) - [:PARENT_OF] -> (AL) - [:PARENT_OF] -> (A) "\
                "WHERE C.type='AST_CALL' AND N.childnum=0 AND S.code='define' " \
                "AND AL.type='AST_ARG_LIST' AND A.childnum=0 AND A.type='string' " \
                f"AND A.code IN {consts.__str__()} RETURN C"
        global_def_nodes.extend([node for node, in self.analyzer.basic_step.run(query)])

        for global_def_node in global_def_nodes:
            temp_file = self.analyzer.fig_step.get_belong_file(global_def_node)
            endlineno = global_def_node[NODE_LINENO]
            global_def_code = "\n".join(self.cat_lines_from_file(temp_file, (global_def_node[NODE_LINENO], endlineno)))
            global_def_code += '\n'
            dep_code = global_def_code + dep_code
        return dep_code

    def resolve_function_definition(self, decl_node: py2neo.Node):
        all_dep_nodes = []
        all_dep_nodes = self.collect_dep_nodes(decl_node)
        all_dep_nodes = list(OrderedDict((node[NODE_INDEX], node) for node in all_dep_nodes).values())

        import time as _t
        logger.info(f"    [resolve_func_def] processing {len(all_dep_nodes)} dep nodes...")
        all_dep_code = ""
        for i, dep_node in enumerate(all_dep_nodes[::-1]):
            _t0 = _t.time()
            # 跳过已经在其他调用链中处理过的函数
            if dep_node[NODE_INDEX] in self._processed_decl_ids and dep_node[NODE_INDEX] != decl_node[NODE_INDEX]:
                continue
            self._processed_decl_ids.add(dep_node[NODE_INDEX])
            # 获取函数名：优先用 name 属性（phpjoern 标准），fallback 到 code_step
            dep_func_name = dep_node.get(NODE_NAME) or self.analyzer.code_step.get_node_code(dep_node)
            # 如果仍然是 NOT_SUPPORT 开头的，尝试第一个子节点的 code
            if dep_func_name and dep_func_name.startswith('NOT_SUPPORT'):
                dep_func_name = dep_node.get(NODE_NAME, 'unknown_func')
            dep_file = self.analyzer.fig_step.get_belong_file(dep_node)
            # 如果找不到源文件路径，跳过此节点（避免读取空路径）
            if not dep_file:
                logger.info(f"    [resolve_func_def] {i+1}/{len(all_dep_nodes)} '{dep_func_name}' - no file, skipped")
                continue
            lineno_range = (dep_node[NODE_LINENO], dep_node[NODE_ENDLINENO])
            dep_lines = self.cat_lines_from_file(dep_file, lineno_range)
            dep_code = "\n".join(dep_lines)
            if dep_node[NODE_TYPE] in {TYPE_METHOD, TYPE_STATIC}:
                dep_code = re.sub(r'^\s*(public|protected|private)\s+', '', dep_code)
                dep_code = re.sub(r'^\s*(static)\s+', '', dep_code)
            # 跳过 handle_undefined_dims/vars 和 handle_nonlocal_functions
            # 这些处理在大型项目上极慢（每次都做全局 Cypher 查询）
            # 对于 function_definition.php，函数体直接从源文件复制即可
            # fuzzer 会通过 GET 参数注入需要的值
            dep_code = re.sub(r'(\$?[\w\[\'"\]\(\)]+->)+(\w+\s*\()', r'\2', dep_code)
            dep_code = re.sub(r'(\$?[\w\[\'"\]\(\)]+->)+([\w\[\'"\]]+)', r'$\2', dep_code)
            dep_code = re.sub(r'([\$?\w\[\'"\]\(\)]+::)+(\w+\s*\()', r'\2', dep_code)
            dep_code = re.sub(r'(\$?[\w\[\'"\]\(\)]+::)+([\w\[\'"\]]+)', f'{generate_temporary_var()}', dep_code)
            dep_code = re.sub(r'(\\\w+)+\\', '', dep_code)
            dep_code = re.sub(r'\$this([^\w])', rf'{generate_temporary_var()}\1', dep_code)
            dep_code = re.sub(r'mixed\s+\$', '$', dep_code)
            # 跳过 handle_global_defs（也有慢查询），直接输出函数定义
            
            elapsed = _t.time() - _t0
            if elapsed > 1.0:
                logger.warning(f"    [resolve_func_def] {i+1}/{len(all_dep_nodes)} '{dep_func_name}' SLOW: {elapsed:.1f}s")
            else:
                logger.info(f"    [resolve_func_def] {i+1}/{len(all_dep_nodes)} '{dep_func_name}' OK: {elapsed:.1f}s")
            
            if dep_code:
                all_dep_code += dep_code
                all_dep_code += "\n\n"
        logger.info(f"    [resolve_func_def] done, generated {len(all_dep_code)} chars of PHP code")
        return all_dep_code

    def run(self):
        definition_code = ""
        stub_code = ""
        self._processed_decl_ids = set()  # 避免同一个函数被重复提取
        self._defined_func_names = set()  # 记录已定义的函数名
        self._stub_func_names = set()  # 记录需要生成 stub 的函数名
        
        for node_id in self.call_site_series:
            call_node = self.analyzer.get_node_itself(node_id)
            decl_nodes = self.analyzer.cg_step.find_decl_nodes(call_node)
            if not decl_nodes:
                # 如果通过 CALLS 边找不到声明，使用名称+参数数量匹配
                decl_nodes = self.analyzer.cg_step.match_decl_nodes(call_node)
            if decl_nodes:
                for decl_node in decl_nodes:
                    if decl_node[NODE_INDEX] in self._processed_decl_ids:
                        continue  # 跳过已处理过的函数声明
                    self._processed_decl_ids.add(decl_node[NODE_INDEX])
                    func_code = self.resolve_function_definition(decl_node)
                    definition_code += func_code
                    # 记录已提取的函数名
                    func_name = decl_node.get(NODE_NAME) or ''
                    if func_name:
                        self._defined_func_names.add(func_name)
            else:
                # 找不到声明：记录函数名，稍后生成 stub
                if call_node[NODE_TYPE] == TYPE_CALL:
                    func_name = self.analyzer.code_step.get_ast_call_code(call_node)
                elif call_node[NODE_TYPE] == TYPE_STATIC_CALL:
                    func_name = self.analyzer.code_step.get_ast_static_call_code(call_node)
                else:
                    func_name = None
                if func_name and func_name not in PHP_BUILT_IN_FUNCTIONS:
                    self._stub_func_names.add(func_name)
        
        # 为深层依赖中无法提取的函数也收集 stub 需求
        # （resolve_function_definition 内部调用的函数如果超出 depth 也需要 stub）
        # 这里通过扫描已生成代码中的函数调用来发现缺失函数
        if definition_code:
            import re as _re
            # 先从真实定义代码中提取所有已定义的函数名
            defined_in_code = set(_re.findall(r'^\s*function\s+([a-zA-Z_]\w*)\s*\(', definition_code, _re.MULTILINE))
            self._defined_func_names.update(defined_in_code)
            
            # 匹配函数调用模式 funcname(
            called_in_defs = set(_re.findall(r'\b([a-zA-Z_]\w*)\s*\(', definition_code))
            # PHP 保留字（不能作为函数名，生成 stub 会导致语法错误）
            php_reserved = {'function', 'if', 'elseif', 'else', 'while', 'for', 'foreach', 
                           'switch', 'case', 'default', 'break', 'continue', 'return',
                           'global', 'static', 'new', 'class', 'interface', 'abstract', 
                           'final', 'throw', 'catch', 'try', 'define', 'defined',
                           'array', 'list', 'isset', 'empty', 'unset', 'echo', 'print',
                           'true', 'false', 'null', 'and', 'or', 'xor', 'not',
                           'die', 'exit', 'eval', 'include', 'require', 'include_once', 'require_once',
                           'var', 'const', 'public', 'private', 'protected', 'extends', 'implements',
                           'namespace', 'use', 'trait', 'yield', 'fn', 'match', 'enum',
                           'int', 'float', 'string', 'bool', 'void', 'object', 'mixed',
                           'self', 'parent', 'clone', 'instanceof'}
            for called_name in called_in_defs:
                if (called_name not in self._defined_func_names 
                    and called_name not in PHP_BUILT_IN_FUNCTIONS
                    and called_name not in php_reserved
                    and not called_name[0].isupper()  # 排除类名（首字母大写）
                    and len(called_name) > 1):  # 排除单字母
                    self._stub_func_names.add(called_name)
        
        # 生成 stub 函数（统一返回第一个参数，保证 PHP 不崩）
        for stub_name in sorted(self._stub_func_names):
            if stub_name not in self._defined_func_names:
                stub_code += f"function {stub_name}() {{ return func_num_args() > 0 ? func_get_arg(0) : null; }}\n\n"
        
        # 组合：先放 stub（被其他函数调用），再放真实定义
        final_code = stub_code + definition_code
        
        # 添加 <?php ?> 标签，确保是合法 PHP 文件
        if final_code.strip():
            final_code = "<?php\n" + final_code + "?>\n"
        
        with open(os.path.join(self.def_storage_path, "function_definition.php"), "w") as f:
            f.write(final_code)
            f.flush()
