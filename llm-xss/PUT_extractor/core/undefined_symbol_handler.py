import os, json
import py2neo
import re
from collections import OrderedDict

from config import STORAGE_PATH, NONLOCAL_FUNCTIONS
from core.neo4j_engine import Neo4jEngine
from core.model import PHP_BUILT_IN_FUNCTIONS
from core.neo4j_engine.const import *
from core.helper import generate_temporary_var
from typing import Union, List, Tuple

class UndefinedSymbolHandler:
    def __init__(self, analyzer: Neo4jEngine, taint_flow: List[int], code: str):
        self.analyzer = analyzer
        self.taint_flow = taint_flow
        self.code = code
        # self.__compile_storage_path()  # 方法不存在，注释掉

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
        except UnicodeDecodeError:
            return []

    def handle_undefined_dims(self) -> str:
        # 遍历 taint_flow 中的每个节点，收集所有 DIM 节点
        dim_nodes = []
        for node in self.taint_flow:
            dim_nodes.extend(self.analyzer.filter_ast_child_nodes(node, node_type_filter=[TYPE_DIM]))

        dim_body_codes = [self.analyzer.code_step.get_ast_dim_body_code(dim_node)[1:] for dim_node in dim_nodes]
        
        # 从 taint_flow 节点对象列表中提取节点 ID
        taint_flow_ids = [node[NODE_INDEX] for node in self.taint_flow]
        
        query = "MATCH (A:AST) - [:PARENT_OF] -> (P) - [:PARENT_OF*0..] -> (V) - [:PARENT_OF] -> (S) " \
                "WHERE A.type='AST_ASSIGN' AND P.childnum=0 AND V.type='AST_VAR' AND S.type='string' " \
                f"AND A.id IN {taint_flow_ids.__str__()} AND S.code IN {dim_body_codes.__str__()} RETURN V"
        potential_defined_nodes = [node for node, in self.analyzer.basic_step.run(query)]
        defined_dim_body_codes = []
        defined_dim_codes = []
        for potential_defined_node in potential_defined_nodes:
            parent_node = self.analyzer.ast_step.get_parent_node(potential_defined_node)
            if parent_node is not None and parent_node[NODE_TYPE] == TYPE_DIM:
                defined_dim_codes.append(self.analyzer.code_step.get_ast_dim_code(parent_node))
            else:
                defined_dim_body_codes.append(self.analyzer.code_step.get_ast_var_code(potential_defined_node))

        undefined_dim_codes = []
        for dim_node in dim_nodes:
            dim_body_code = self.analyzer.code_step.get_ast_dim_body_code(dim_node)
            if 'NOT_SUPPORT_FOR' in dim_body_code:
                continue
            if dim_body_code in defined_dim_body_codes:
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
        self.code = code_to_insert + self.code
        return self.code

    def handle_undefined_vars(self) -> str:
        # 遍历 taint_flow 中的每个节点，收集所有 VAR 节点
        var_nodes = []
        for node in self.taint_flow:
            var_nodes.extend(self.analyzer.filter_ast_child_nodes(node, node_type_filter=[TYPE_VAR]))
        
        normal_vars = [self.analyzer.code_step.get_ast_var_code(var_node)[1:] for var_node in var_nodes]
        
        # 从 taint_flow 节点对象列表中提取节点 ID
        taint_flow_ids = [node[NODE_INDEX] for node in self.taint_flow]
        
        query = "MATCH (A:AST) - [:PARENT_OF] -> (P) - [:PARENT_OF*0..] -> (V) - [:PARENT_OF] -> (S) " \
                "WHERE A.type='AST_ASSIGN' AND P.childnum=0 AND V.type='AST_VAR' AND S.type='string' " \
                f"AND A.id IN {taint_flow_ids.__str__()} AND S.code IN {normal_vars.__str__()} RETURN V"
        defined_vars = [self.analyzer.code_step.get_ast_var_code(n) 
                            for n, in self.analyzer.basic_step.run(query)]
        
        # 从 taint_flow 中查找所有函数声明节点的参数
        param_nodes = []
        for node in self.taint_flow:
            # 检查节点是否是函数声明类型
            if node[NODE_TYPE] in FUNCTION_DECLARE_TYPES:
                try:
                    param_nodes.extend(self.analyzer.ast_step.find_function_param_node_list(node))
                except (AssertionError, IndexError):
                    # 如果节点不支持参数查找，跳过
                    continue
        
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
        self.code = code_to_insert + self.code
        return self.code

    def handle_nonlocal_functions(self) -> str:
        def replace_callback(match: re.Match):
            if match.group(1) is not None:
                return match.group(0)
            full_text = match.group(0)
            parenthesis_stack = []
            ret = ''
            for index in range(len(full_text)):
                char = full_text[index]
                if char == '(':
                    parenthesis_stack.append(char)
                elif char == ')':
                    parenthesis_stack = parenthesis_stack[:-1]
                    if len(parenthesis_stack) == 0:
                        return f'{generate_temporary_var()}{full_text[index+1:]}'
        
        re_pattern = fr'(function\s+\w*)?@?({"|".join(NONLOCAL_FUNCTIONS)})\s*\([^;{"{"}]+'
        self.code = re.sub(re_pattern, replace_callback, self.code)
        return self.code

    def handle_global_defs(self):
        global_def_nodes = []
        
        # 遍历 taint_flow 中的每个节点，收集所有 GLOBAL 和 CONST 节点
        global_nodes = []
        const_nodes = []
        for node in self.taint_flow:
            global_nodes.extend(self.analyzer.filter_ast_child_nodes(node, node_type_filter=[TYPE_GLOBAL]))
            const_nodes.extend(self.analyzer.filter_ast_child_nodes(node, node_type_filter=[TYPE_CONST]))
        
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
            self.code = global_def_code + self.code
        return self.code

    def run(self):
        self.handle_undefined_dims()
        self.handle_undefined_vars()
        self.handle_nonlocal_functions()
        self.code = re.sub(r'(\$?[\w\[\'"\]\(\)]+->)+(\w+\s*\()', r'\2', self.code)
        self.code = re.sub(r'(\$?[\w\[\'"\]\(\)]+->)+([\w\[\'"\]]+)', r'$\2', self.code)
        self.code = re.sub(r'([\$?\w\[\'"\]\(\)]+::)+(\w+\s*\()', r'\2', self.code)
        self.code = re.sub(r'(\$?[\w\[\'"\]\(\)]+::)+([\w\[\'"\]]+)', f'{generate_temporary_var()}', self.code)
        self.code = re.sub(r'(\\\w+)+\\', '', self.code)
        self.code = re.sub(r'\$this([^\w])', rf'{generate_temporary_var()}\1', self.code)
        self.code = re.sub(r'mixed\s+\$', '$', self.code)
        self.handle_global_defs()
        return self.code
