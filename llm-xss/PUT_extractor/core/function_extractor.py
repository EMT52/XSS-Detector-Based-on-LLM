import os
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
from core.php_source import IDENTIFIER, METHOD_MODIFIERS, PhpSource

PHP_BUILTIN_NAMES = frozenset(map(php_symbol_key, PHP_BUILT_IN_FUNCTIONS))

class FunctionExtractor(object):
    def __init__(self, target: str, analyzer: Neo4jEngine, path_id: int, call_site_series: List[int]):
        self.analyzer = analyzer
        self.target = target
        self.call_site_series = call_site_series
        self.path_id = path_id
        self.__compile_storage_path()
        self._declarations = {}
        self._call_names = {}
        self._body_calls = {}
        self._member_names = {}
        self._global_names = set(PHP_BUILTIN_NAMES)
        self._required_names = {}
        self._defined_names = set()

    def __compile_storage_path(self):
        def_storage_basedir = os.path.join(STORAGE_PATH, 'PUT')
        self.def_storage_path = os.path.join(def_storage_basedir, self.target, str(self.path_id))
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
                        selected_lines.append(line.rstrip('\r\n'))
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

    def _call_name_node(self, call_node):
        call_id = call_node[NODE_INDEX]
        if call_id not in self._call_names:
            self._call_names[call_id] = self.analyzer.cg_step.get_call_name_node(call_node)
        return self._call_names[call_id]

    def _global_call_name(self, call_node):
        name = self._call_name_node(call_node)
        if name is not None and name[NODE_CODE]:
            name = name[NODE_CODE].strip('"').strip("'").lstrip('\\')
            if IDENTIFIER.fullmatch(name):
                return name
        return None

    def _resolve_declaration(self, call_node):
        call_id = call_node[NODE_INDEX]
        if call_id not in self._declarations:
            expected_type = CALL_DECLARATION_TYPES[call_node[NODE_TYPE]]
            candidates = {}
            if expected_type == TYPE_FUNC_DECL:
                name = self._global_call_name(call_node)
                builtin = name and php_symbol_key(name) in PHP_BUILTIN_NAMES
                if builtin and not self.analyzer.cg_step.get_call_namespace(call_node):
                    self._declarations[call_id] = None
                    return None

            for lookup in (self.analyzer.cg_step.find_decl_nodes, self.analyzer.cg_step.match_decl_nodes):
                candidates = {node[NODE_INDEX]: node for node in lookup(call_node)
                              if node[NODE_TYPE] == expected_type}
                if candidates:
                    break
            self._declarations[call_id] = next(iter(candidates.values())) if len(candidates) == 1 else None
        return self._declarations[call_id]

    def _member_symbol(self, kind, node_id):
        key = (kind, node_id)
        if key not in self._member_names:
            global_declarations = self.analyzer.cg_step.global_function_names
            symbol = f"__put_{kind}_{node_id}"
            while symbol in self._global_names or symbol in global_declarations:
                symbol += '_'
            self._member_names[key] = symbol
        return self._member_names[key]

    def member_call_symbol(self, call_node):
        declaration = self._resolve_declaration(call_node)
        if declaration is None:
            name = self._member_symbol('member_stub', call_node[NODE_INDEX])
        else:
            name = self._member_symbol('method', declaration[NODE_INDEX])
        self._required_names[name] = name
        return name

    def _register_global_calls(self, calls):
        for call in calls:
            if call[NODE_TYPE] == TYPE_CALL:
                name = self._global_call_name(call)
                if name:
                    key = php_symbol_key(name)
                    self._global_names.add(key)
                    if key not in PHP_BUILTIN_NAMES:
                        self._required_names.setdefault(key, name)

    def _get_body_calls(self, declaration):
        decl_id = declaration[NODE_INDEX]
        if decl_id not in self._body_calls:
            self._body_calls[decl_id] = self.analyzer.filter_ast_child_nodes(
                declaration, node_type_filter=set(CALL_DECLARATION_TYPES)
            )
        return self._body_calls[decl_id]

    def resolve_function_definition(self, decl_node: py2neo.Node):
        source_path = self.analyzer.fig_step.get_belong_file(decl_node)
        if not source_path or "PHPJOERN_PREDEFINE.php" in source_path:
            return ''
        name = decl_node.get(NODE_NAME)
        if not name:
            name_node = self.analyzer.ast_step.get_ith_child_node(decl_node, 0, ignore_error_flag=True)
            name = name_node and name_node.get(NODE_CODE)
            if not name:
                return ''
            name = name.strip('"').strip("'")
        line_range = (int(decl_node[NODE_LINENO]), int(decl_node[NODE_ENDLINENO]))
        code = '\n'.join(self.cat_lines_from_file(source_path, line_range))
        if not code:
            return ''

        source = PhpSource(code, line_range[0])
        declarations = list(source.declarations(name, *line_range))
        if len(declarations) > 1:
            # Line-only AST positions can include multiple same-named functions.
            # Read the surrounding class scopes to select the actual declaration.
            with open(source_path, encoding='utf-8', errors='ignore') as file:
                source = PhpSource(file.read(), fragment=False)
            owner = decl_node.get('classname') if decl_node[NODE_TYPE] == TYPE_METHOD else None
            owner = php_symbol_key(owner) if owner else None
            declarations = [item for item in source.declarations(name, *line_range)
                            if source.declaration_owner(item[0]) == owner]
        if len(declarations) != 1:
            logger.warning("Could not locate declaration %s at %s:%s", name, source_path, line_range[0])
            return ''
        function_index, name_index, body_end = declarations[0]
        tokens = source.tokens
        first = function_index
        edits = []
        calls = self._get_body_calls(decl_node)
        self._register_global_calls(calls)
        if decl_node[NODE_TYPE] == TYPE_METHOD:
            while first and tokens[first - 1].kind in METHOD_MODIFIERS:
                first -= 1
                edits.append((tokens[first].start, tokens[first].end, ''))
            name = self._member_symbol('method', decl_node[NODE_INDEX])
            edits.append((tokens[name_index].start, tokens[name_index].end, name))

        bindings = []
        for call in calls:
            if call[NODE_TYPE] == TYPE_CALL:
                continue
            name_node = self._call_name_node(call)
            if name_node is None:
                name_expr = self.analyzer.ast_step.get_ith_child_node(call, 1, ignore_error_flag=True)
                if name_expr is None:
                    continue
                member_name = None
            else:
                name_expr = name_node
                member_name = (name_node[NODE_CODE] or '').strip('"').strip("'")
            bindings.append((call[NODE_TYPE], member_name, name_expr[NODE_INDEX],
                             call[NODE_LINENO], self.member_call_symbol(call)))
        edits.extend(source.member_edits(name_index, body_end, bindings))
        edits.extend(source.normalization_edits(generate_temporary_var, first, body_end))
        self._defined_names.add(php_symbol_key(name))
        start, end = source.declaration_bounds(first, body_end)
        return source.render(edits, start, end) + '\n\n'

    def run(self):
        calls = [self.analyzer.get_node_itself(node_id) for node_id in self.call_site_series]
        self._register_global_calls(calls)
        declarations = {}
        for call in calls:
            declaration = self._resolve_declaration(call)
            if declaration is not None:
                declarations[declaration[NODE_INDEX]] = declaration
        # Only entry-path declarations are extracted. Calls inside them keep
        # their binding, with a stub when the target is outside that depth.
        for declaration in declarations.values():
            self._register_global_calls(self._get_body_calls(declaration))
        for call in calls:
            if call[NODE_TYPE] != TYPE_CALL:
                self.member_call_symbol(call)

        definitions = ''.join(self.resolve_function_definition(node) for node in declarations.values())
        stubs = ''.join(
            f"function {name}() {{ return func_num_args() > 0 ? func_get_arg(0) : null; }}\n\n"
            for key, name in sorted(self._required_names.items()) if key not in self._defined_names
        )
        code = stubs + definitions
        with open(os.path.join(self.def_storage_path, "function_definition.php"), "w") as file:
            if code:
                file.write("<?php\n" + code + "?>\n")
