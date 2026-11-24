import logging
from abc import ABC
from typing import List, Set, Tuple, Union
from collections import deque

import Levenshtein
import networkx as nx
import py2neo

from .const import *

logger = logging.getLogger(__name__)


class AbstractStep(ABC):
    def __init__(self, parent, step_name="abstract_step"):
        self.parent = parent
        self.__step_name = step_name

    def __str__(self):
        return self.__step_name

    @property
    def step_name(self):
        return self.__step_name


class ASTStep(AbstractStep):

    def __init__(self, parent):
        super().__init__(parent, "ast_step")

    def find_parent_nodes(self, _node: py2neo.Node) -> List[py2neo.Node]:
        res = [i.start_node for i in
               self.parent.neo4j_graph.relationships.match(nodes=[None, _node], r_type=AST_EDGE, )]
        return list(sorted(res, key=lambda x: x[NODE_INDEX]))

    def find_child_nodes(self, _node: py2neo.Node, include_type: List[str] = None) -> List[py2neo.Node]:
        ast_rels = self.parent.neo4j_graph.relationships.match(nodes=[_node, None], r_type=AST_EDGE, ).all()
        res = [i.end_node for i in ast_rels]
        res_ = []
        for i in res:
            if include_type is not None:
                if i[NODE_TYPE] in include_type:
                    res_.append(i)
            else:
                res_.append(i)
        return list(sorted(res_, key=lambda x: x[NODE_INDEX]))

    def get_ith_parent_node(self, _node: py2neo.Node, i: int = 0, ignore_error_flag=False) -> py2neo.Node | None:
        _node_cp = self.parent.find_ast_parent_nodes(_node)
        if i <= (_node_cp.__len__() - 1):
            return _node_cp[i]
        else:
            if ignore_error_flag:
                return None
            else:
                raise IndexError()

    def get_parent_node(self, _node: py2neo.Node, ignore_error_flag=False) -> Union[py2neo.Node, None]:
        return self.get_ith_parent_node(_node, ignore_error_flag=ignore_error_flag)

    def get_child_node(self, _node: py2neo.Node, ignore_error_flag=False) -> py2neo.Node:
        return self.get_ith_child_node(_node, ignore_error_flag=ignore_error_flag)

    def get_ith_child_node(self, _node: py2neo.Node, i: int = 0, ignore_error_flag=False) -> py2neo.Node | None:
        _node_cp = self.find_child_nodes(_node)
        if i <= (_node_cp.__len__() - 1):
            return _node_cp[i]
        else:
            if ignore_error_flag:
                return None
            else:
                raise IndexError()

    def filter_parent_nodes(self, _node: py2neo.Node, max_depth=20, not_include_self: bool = False,
                            node_type_filter: set = FUNCTION_CALL_TYPES | FUNCTION_DECLARE_TYPES) \
            -> Union[py2neo.Node, None]:
        if _node[NODE_TYPE] in node_type_filter:
            return _node
        __node = self.get_parent_node(_node)
        if __node[NODE_TYPE] in node_type_filter:
            return __node
        elif __node[NODE_TYPE] in {TYPE_STMT_LIST}:
            return None
        else:
            return self.filter_parent_nodes(__node, max_depth=max_depth, not_include_self=not_include_self,
                                            node_type_filter=node_type_filter)

    def filter_child_nodes(self, _node: py2neo.Node, max_depth=20, not_include_self: bool = False,
                           node_type_filter: Union[List[str], str, Set[str]] = None) -> List[py2neo.Node]:
        if _node[NODE_INDEX] is None:
            _node = _node.graph.nodes.get(_node.identity)
        node_id = _node[NODE_INDEX]
        
        if isinstance(node_type_filter, str):
            node_type_filter = [node_type_filter]
        elif isinstance(node_type_filter, Set):
            node_type_filter = [i for i in node_type_filter]
        
        # 优化：对函数声明节点，利用 funcid 直接筛选内部节点（O(1) 索引查询）
        # 带缓存：同一个 funcid + 类型过滤的查询只执行一次
        if _node[NODE_TYPE] in FUNCTION_DECLARE_TYPES and node_type_filter is not None:
            if not hasattr(self.parent, '_filter_child_cache'):
                self.parent._filter_child_cache = {}
            cache_key = f"{node_id}_{str(sorted(node_type_filter))}"
            if cache_key in self.parent._filter_child_cache:
                return self.parent._filter_child_cache[cache_key]
            query = (f"MATCH (B:AST) WHERE B.funcid = '{node_id}' "
                     f"AND B.type in {node_type_filter.__str__()} "
                     f"RETURN B")
            results = [b for b, in self.parent.run(query)]
            self.parent._filter_child_cache[cache_key] = results
            if results:
                return results
        
        # 通用 fallback：使用可变长度路径（适用于非函数声明节点或需要不含类型过滤的情况）
        query = (f"MATCH (A:AST)-[:PARENT_OF*{not_include_self.__int__()}..{max_depth}]->(B:AST) "
                 f"WHERE A.id = '{node_id}' ")
        if node_type_filter is not None:
            query += f" AND B.type in {node_type_filter.__str__()}"
        return [b for b, in self.parent.run(
                query + " RETURN B;"
        )]

    def __has_cfg(self, node):
        return self.parent.basic_step.match_relationship({node}, r_type=CFG_EDGE).exists()

    def get_root_node(self, node: py2neo.Node) -> py2neo.Node:
        assert node is not None
        if node[NODE_TYPE] in {TYPE_FUNC_DECL, TYPE_PARAM_LIST, }:
            return node
        parent_node = self.get_parent_node(node)
        if node[NODE_TYPE] in {TYPE_IF}:
            return self.get_child_node(self.get_child_node(node))
        elif node[NODE_TYPE] in {TYPE_IF_ELEM}:
            node = self.get_child_node(node, ignore_error_flag=True)
            if node is None:
                raise NotImplementedError()
            else:
                return node
        elif node[NODE_TYPE] in {TYPE_WHILE}:
            return self.get_child_node(node)
        elif node[NODE_TYPE] in {TYPE_SWITCH_CASE}:
            return self.get_child_node(self.get_parent_node(self.get_parent_node(node)))
        elif parent_node and parent_node in {TYPE_SWITCH_CASE}:
            return self.get_child_node(
                    self.get_parent_node(self.get_parent_node(self.get_parent_node(node))))
        elif parent_node[NODE_TYPE] in {TYPE_IF_ELEM}:
            return self.get_root_node(parent_node)

        while not self.__has_cfg(node) and node is not None:
            _node = self.get_parent_node(node, ignore_error_flag=True)
            if _node is None:
                return None
            node = _node
        return node

    def get_control_node_condition(self, _node: py2neo.Node, ignore_error=False) -> py2neo.Node:
        if not ignore_error:
            assert _node[NODE_TYPE] in {TYPE_IF, TYPE_IF_ELEM, TYPE_WHILE, TYPE_DO_WHILE}
        else:
            if _node[NODE_TYPE] not in {TYPE_IF, TYPE_IF_ELEM, TYPE_WHILE, TYPE_DO_WHILE}:
                return _node
        if _node[NODE_TYPE] in {TYPE_WHILE, TYPE_DO_WHILE, TYPE_IF_ELEM}:
            return self.get_ith_child_node(_node, 0)
        if _node[NODE_TYPE] in {TYPE_IF}:
            return self.get_ith_child_node(
                    self.get_ith_child_node(_node, 0), 0
            )

    def find_function_return_expr(self, node: py2neo.Node, ) -> List[py2neo.Node]:
        res = []
        func_exit = self.parent.match_first(LABEL_ARTIFICIAL,
                                            **{NODE_FUNCID: node[NODE_INDEX],
                                               NODE_FILEID: node[NODE_FILEID],
                                               NODE_TYPE: TYPE_CFG_FUNC_EXIT})
        for r in self.parent.match_relationship([None, func_exit], r_type=CFG_EDGE):
            res.append(r.start_node)
        return sorted(res, key=lambda x: x[NODE_INDEX])

    def find_function_entrance_expr(self, node: py2neo.Node, ) -> List[py2neo.Node]:
        res = []
        func_entry = self.parent.match_first(LABEL_ARTIFICIAL,
                                             **{NODE_FUNCID: node[NODE_INDEX],
                                                NODE_FILEID: node[NODE_FILEID],
                                                NODE_TYPE: TYPE_CFG_FUNC_ENTRY})
        for r in self.parent.match_relationship([func_entry, None], r_type=CFG_EDGE):
            res.append(r.end_node)
        return sorted(res)

    def find_function_param_node_list(self, node:py2neo.Node) -> List[py2neo.Node]:
        assert node[NODE_TYPE] in FUNCTION_DECLARE_TYPES, f'Param search are not supported for {node}'
        return self.find_child_nodes(
                self.find_child_nodes(node, include_type=[TYPE_PARAM_LIST])[0]
        )

    def get_function_arg_ith_node(self, node: py2neo.Node, i=0) -> py2neo.Node:
        if node[NODE_TYPE] in {TYPE_EXIT, TYPE_ECHO,
                               TYPE_INCLUDE_OR_EVAL,
                               TYPE_PRINT, TYPE_RETURN,
                               TYPE_UNSET, TYPE_ISSET}:
            arg_list = self.find_child_nodes(node)
            return arg_list[i]
        arg_list = self.find_function_arg_node_list(node)
        if arg_list.__len__() == 0:
            return None
        else:
            try:
                return arg_list[i]
            except IndexError as e:
                return None

    def find_function_arg_node_list(self, node: py2neo.Node) -> List[py2neo.Node]:
        if node[NODE_TYPE] in {TYPE_INCLUDE_OR_EVAL, TYPE_ECHO, TYPE_PRINT, TYPE_EXIT, TYPE_CAST, TYPE_RETURN}:
            return self.find_child_nodes(node)
        
        arg_list_nodes = self.find_child_nodes(node, include_type=[TYPE_ARG_LIST])
        if not arg_list_nodes:
            return []
        return self.find_child_nodes(arg_list_nodes[0])

    def get_function_arg_node_cnt(self, node: py2neo.Node) -> int:
        if node[NODE_TYPE] in {TYPE_EXIT, TYPE_ECHO, TYPE_INCLUDE_OR_EVAL, TYPE_PRINT, TYPE_RETURN}:
            return 1
        arg_list = self.find_function_arg_node_list(node)
        if arg_list.__len__() == 0:

            return 0
        else:
            try:
                return arg_list.__len__()
            except IndexError as e:

                return 1

    def get_function_defined_node_by_name(self, name: str, match_matrix=None):
        if match_matrix is None:
            match_matrix = {}
        if "new " in name:
            name = name.replace("new", "").strip()
            return self.parent.get_class_construct_function(
                    self.parent.get_class_defined_node_by_name(name, **match_matrix)
            )
        return self.parent.neo4j_graph.nodes.match("AST", **match_matrix).where(
                f"_.name='{name}' and _.type in ['AST_METHOD','AST_FUNC_DECL']"
        ).first()

    def get_class_defined_node_by_name(self, name: str, match_matrix=None):
        if match_matrix is None:
            match_matrix = {}
        return self.parent.neo4j_graph.nodes.match("AST", **match_matrix).where(
                f"_.name='{name}' AND _.type='AST_CLASS'"
        ).first()

    def get_class_construct_function(self, node: py2neo.Node):
        class_top_level_node = self.parent.find_ast_child_nodes(node, include_type=[TYPE_TOPLEVEL])[0]
        class_stmt_list_node = self.parent.find_ast_child_nodes(class_top_level_node, include_type=[TYPE_STMT_LIST])[0]
        for i in self.parent.find_ast_child_nodes(class_stmt_list_node, include_type=[TYPE_METHOD]):
            if i[NODE_NAME] == "__construct":
                return i
        return None
    
    def find_sources(self, node: py2neo.Node) -> List[py2neo.Node]:
        if node[NODE_TYPE] in {TYPE_FOREACH}:
            node = self.parent.ast_step.get_ith_child_node(node, 0)
        candidate_dim_nodes = self.filter_child_nodes(node, node_type_filter=[TYPE_DIM], )
        source_vars = [self.parent.code_step.get_ast_dim_code(n) for n in candidate_dim_nodes 
                        if self.parent.code_step.get_ast_dim_body_code(n) in 
                        {"$_POST", "$_GET", "$_REQUEST", "$_FILE", "$_COOKIE"}]

        return source_vars


class BasicStep(AbstractStep):
    def __init__(self, parent):
        super().__init__(parent, "basic_step")
        self.neo4j_graph = parent.neo4j_graph

    def run(self, query) -> py2neo.NodeMatch:
        tx = self.neo4j_graph.begin()
        try:
            res = tx.run(query)
            tx.commit()
            return res
        except Exception as e:
            tx.rollback()
            raise e

    def run_and_fetch_one(self, query) -> py2neo.NodeMatch:
        tx = self.neo4j_graph.begin()
        try:
            res = tx.run(query)
            tx.commit()
            for i in res:
                return i
            return None
        except Exception as e:
            tx.rollback()
            raise e

    def match(self, *args, **kwargs) -> py2neo.NodeMatch:
        return self.neo4j_graph.nodes.match(*args, **kwargs)

    def match_first(self, *args, **kwargs) -> py2neo.Node:
        return self.neo4j_graph.nodes.match(*args, **kwargs).first()

    def match_relationship(self, *args, **kwargs) -> py2neo.RelationshipMatch:
        return self.neo4j_graph.relationships.match(*args, **kwargs)

    def match_first_relationship(self, *args, **kwargs) -> py2neo.Relationship:
        return self.neo4j_graph.relationships.match(*args, **kwargs).first()

    def get_node_itself(self, _id: int) -> py2neo.Node:
        node = self.neo4j_graph.nodes.match(id=_id).limit(1).first()
        if node is None:
            # Fallback: use Cypher query with string ID (Neo4j 4.4 uses STRING type for IDs)
            result = list(self.run(f"MATCH (n) WHERE n.id='{_id}' RETURN n LIMIT 1"))
            if result:
                node = result[0]['n']
            else:
                # 输出详细的调试信息
                logger.error(f"❌ Node with id={_id} not found in database")
                logger.error(f"   Tried queries:")
                logger.error(f"   1. self.neo4j_graph.nodes.match(id={_id})")
                logger.error(f"   2. MATCH (n) WHERE n.id='{_id}' RETURN n")
                
                # 尝试查询数据库中的节点总数和ID范围
                try:
                    count_result = list(self.run("MATCH (n) RETURN count(n) as cnt"))
                    if count_result:
                        total_nodes = count_result[0]['cnt']
                        logger.error(f"   Database has {total_nodes} nodes in total")
                    
                    # 查询数据库中的ID范围
                    id_range_result = list(self.run("MATCH (n) WHERE n.id IS NOT NULL RETURN min(n.id) as min_id, max(n.id) as max_id"))
                    if id_range_result:
                        min_id = id_range_result[0]['min_id']
                        max_id = id_range_result[0]['max_id']
                        logger.error(f"   Node ID range in database: {min_id} to {max_id}")
                    
                    # 查询几个示例节点ID
                    sample_result = list(self.run("MATCH (n) WHERE n.id IS NOT NULL RETURN n.id as id LIMIT 5"))
                    if sample_result:
                        sample_ids = [r['id'] for r in sample_result]
                        logger.error(f"   Sample node IDs in database: {sample_ids}")
                except Exception as e:
                    logger.error(f"   Failed to query database info: {e}")
                
                raise ValueError(f"Node with id={_id} not found in database")
        return node

    def get_node_itself_by_identity(self, _id: int):
        return self.neo4j_graph.nodes.get(identity=_id)


class CFGStep(AbstractStep):
    def __init__(self, parent):
        super().__init__(parent, "cfg_step")

    def find_predecessors(self, _node: py2neo.Node) -> List[py2neo.Node]:
        res = [i.start_node for i in
               self.parent.neo4j_graph.relationships.match(nodes=[None, _node], r_type=CFG_EDGE, )]
        return list(sorted(res, key=lambda x: x[NODE_INDEX]))

    def find_successors(self, _node: py2neo.Node) -> List[py2neo.Node]:
        res = [i.end_node for i in
               self.parent.neo4j_graph.relationships.match(nodes=[_node, None], r_type=CFG_EDGE, )]
        return list(sorted(res, key=lambda x: x[NODE_INDEX]))

    def get_flow_label(self, _node_start: py2neo.Node, _node_end: py2neo.Node) -> List[str]:
        return [i.get(CFG_EDGE_FLOW_LABEL) for i in
                self.parent.neo4j_graph.relationships.match(nodes=[_node_start, _node_end], r_type=CALLS_EDGE, )]

    def has_cfg(self, start_node, end_node=None):
        if end_node is None:
            return self.parent.basic_step.match_relationship({start_node}, r_type=CFG_EDGE).exists()
        else:
            return self.parent.basic_step.match_relationship([start_node, end_node], r_type=CFG_EDGE).exists()


class CGStep(AbstractStep):
    def __init__(self, parent):
        super().__init__(parent, "cg_step")

    def find_decl_nodes(self, _node: py2neo.Node) -> List[py2neo.Node]:
        res = [i.end_node for i in
               self.parent.neo4j_graph.relationships.match(nodes=[_node, None], r_type=CALLS_EDGE, )]
        return list(sorted(res, key=lambda x: x[NODE_INDEX]))

    def find_call_nodes(self, _node: py2neo.Node) -> List[py2neo.Node]:
        res = [i.start_node for i in
               self.parent.neo4j_graph.relationships.match(nodes=[None, _node], r_type=CALLS_EDGE, )]
        return list(sorted(res, key=lambda x: x[NODE_INDEX]))
    
    def match_decl_nodes(self, _node: py2neo.Node) -> List[py2neo.Node]:
        if _node[NODE_TYPE] == TYPE_CALL:
            function_name = self.parent.code_step.get_ast_call_code(_node)
            decl_node_type = [TYPE_FUNC_DECL]
        else:
            function_name = self.parent.ast_step.get_ith_child_node(_node, 1)[NODE_CODE]
            decl_node_type = [TYPE_METHOD]
        arg_node_count = self.parent.ast_step.get_function_arg_node_cnt(_node)
        # 方式1: 通过子节点的 code 属性匹配函数名
        matched_decl_nodes = [n for n, in self.parent.basic_step.run(
            f"MATCH (N:AST) - [:PARENT_OF] -> (M) WHERE N.type in {decl_node_type.__str__()} "
            f"AND M.childnum=0 AND M.code='{function_name}' RETURN N"
        )]
        # 方式2: 如果方式1没找到，通过节点自身的 name 属性匹配
        # （phpjoern 某些版本将函数名存储在 AST_FUNC_DECL 节点的 name 属性中，而非子节点的 code）
        if not matched_decl_nodes:
            matched_decl_nodes = [n for n, in self.parent.basic_step.run(
                f"MATCH (N:AST) WHERE N.type in {decl_node_type.__str__()} "
                f"AND N.name='{function_name}' RETURN N"
            )]
        matched_decl_nodes = [n for n in matched_decl_nodes 
                            if self.parent.ast_step.find_function_param_node_list(n).
                            __len__() == arg_node_count]
        return matched_decl_nodes


class CHGStep(AbstractStep):
    def __init__(self, parent):
        super().__init__(parent, "chg_step")

    def get_class_defined_node_by_name(self, name: str):
        return self.parent.neo4j_graph.nodes.match("AST").where(
                f"_.name='{name}' AND _.type='AST_CLASS'"
        ).first()

    def get_class_construct_function(self, node: py2neo.Node):
        class_top_level_node = self.parent.find_ast_child_nodes(node, include_type=[TYPE_TOPLEVEL])[0]
        class_stmt_list_node = self.parent.find_ast_child_nodes(class_top_level_node, include_type=[TYPE_STMT_LIST])[0]
        for i in self.parent.find_ast_child_nodes(class_stmt_list_node, include_type=[TYPE_METHOD]):
            if i[NODE_NAME] == "__construct":
                return i
        return None


def _normalize(x):
    if x is None:
        return None
    return x.strip('\'').strip('\"')


class CodeStep(AbstractStep):
    def __init__(self, parent):
        super(CodeStep, self).__init__(parent, "code_step")
        self._register_lambda_functions()
        self._class_method = {i for i in self.__dir__() if not i.__str__().startswith("_")}

    def _register_lambda_functions(self):
        self.get_string_code = lambda x: _normalize(x[NODE_CODE]) \
            if self._node_type_assertion(x, TYPE_STRING) else None
        self.get_integer_code = lambda x: x[NODE_CODE].__str__() \
            if self._node_type_assertion(x, TYPE_INTEGER) else None
        self.get_double_code = lambda x: x[NODE_CODE].__str__() \
            if self._node_type_assertion(x, TYPE_DOUBLE) else None
        self.get_bool_code = lambda x: x[NODE_CODE].__str__() \
            if self._node_type_assertion(x, TYPE_BOOL) else None
        self.get_ast_method_code = lambda x: x[NODE_NAME].__str__() \
            if self._node_type_assertion(x, TYPE_METHOD) else None
        self.get_ast_function_decl_code = lambda x: x[NODE_NAME].__str__() \
            if self._node_type_assertion(x, TYPE_FUNC_DECL) else None

    def get_node_code(self, node: py2neo.Node, ) -> str:
        code = None
        if node[NODE_TYPE] == TYPE_EXIT:
            code = "exit"
        elif node[NODE_TYPE] == TYPE_METHOD:
            code = self.parent.ast_step.get_ith_child_node(node, 0)[NODE_CODE]
        elif node[NODE_TYPE] == TYPE_FUNC_DECL:
            code = self.parent.ast_step.get_ith_child_node(node, 0)[NODE_CODE]
        elif node[NODE_TYPE] == TYPE_ISSET:
            code = "isset"
        elif node[NODE_TYPE] == TYPE_ECHO:
            code = "echo"
        elif node[NODE_TYPE] == TYPE_PRINT:
            code = "print"
        elif node[NODE_TYPE] == TYPE_RETURN:
            code = "return"
        elif node[NODE_TYPE] == TYPE_UNSET:
            code = "unset"
        elif node[NODE_TYPE] == TYPE_EMPTY:
            code = "empty"
        elif node[NODE_TYPE] == TYPE_INCLUDE_OR_EVAL and (
                set(node[NODE_FLAGS]) & {FLAG_EXEC_INCLUDE, FLAG_EXEC_INCLUDE_ONCE, FLAG_EXEC_REQUIRE,
                                         FLAG_EXEC_REQUIRE_ONCE}):
            if set(node[NODE_FLAGS]) & {FLAG_EXEC_INCLUDE}:
                code = "include"
            if set(node[NODE_FLAGS]) & {FLAG_EXEC_INCLUDE_ONCE}:
                code = "include_once"
            if set(node[NODE_FLAGS]) & {FLAG_EXEC_REQUIRE}:
                code = "require"
            if set(node[NODE_FLAGS]) & {FLAG_EXEC_REQUIRE_ONCE}:
                code = "require_once"
        elif node[NODE_TYPE] == TYPE_BREAK:
            code = "break"
        elif node[NODE_TYPE] == TYPE_INCLUDE_OR_EVAL and (set(node[NODE_FLAGS]) & {FLAG_EXEC_EVAL}):
            code = "eval"
        elif node[NODE_TYPE] == TYPE_NULL:
            code = 'null'

        if code is not None:
            return code

        if "get_{}_code".format(node[NODE_TYPE].lower()) not in self._class_method:
            code = f"NOT_SUPPORT_FOR_{node[NODE_TYPE]}"
        else:
            code = eval("self.get_{}_code(node)".format(node[NODE_TYPE].lower()))
        return code

    def get_ast_new_code(self, node: py2neo.Node) -> str:
        assert node[NODE_TYPE] == TYPE_NEW
        if self.parent.get_ast_child_node(self.parent.get_ast_child_node(node))[NODE_CODE] is not None:
            return self.parent.get_ast_child_node(self.parent.get_ast_child_node(node))[NODE_CODE]
        elif self.parent.get_ast_child_node(node)[NODE_TYPE] == TYPE_PROP:
            return self.get_ast_prop_code(self.parent.get_ast_child_node(node))
        else:
            raise Exception(TYPE_NEW + node.__str__())

    def get_ast_var_code(self, node: py2neo.Node) -> str:
        assert node[NODE_TYPE] == TYPE_VAR
        if NODE_CODE in self.parent.get_ast_child_node(node).keys():
            code = self.parent.get_ast_child_node(node)[NODE_CODE]
            # 【修复】清理变量名中可能存在的引号
            # 原因：Neo4j 中的 NODE_CODE 可能包含 JSON 转义的引号
            # 例如：NODE_CODE 可能是 "user_input"（带引号），导致生成 $"user_input"
            # 清理后生成正确的 $user_input
            code = code.strip('"').strip("'")
            return '$' + code
        elif NODE_CODE in self.parent.get_ast_child_node(self.parent.get_ast_child_node(node)).keys():
            code = self.parent.get_ast_child_node(self.parent.get_ast_child_node(node))[NODE_CODE]
            # 【修复】同样清理引号
            code = code.strip('"').strip("'")
            return '$' + code
        else:
            return '$uk'

        
    def get_ast_param_code(self, node: py2neo.Node) -> str:
        assert node[NODE_TYPE] == TYPE_PARAM
        param_name_node = self.parent.ast_step.get_ith_child_node(node, i=1)
        if NODE_CODE in param_name_node:
            code = param_name_node[NODE_CODE]
            # 【修复】清理参数名中可能存在的引号
            # 原因同 get_ast_var_code，确保生成正确的参数名
            code = code.strip('"').strip("'")
            return '$' + code
        else:
            return '$uk'

    def _node_type_assertion(self, node: py2neo.Node, TYPE):
        assert node[NODE_TYPE] == TYPE
        return True

    def get_ast_const_code(self, node: py2neo.Node) -> str:
        assert node[NODE_TYPE] == TYPE_CONST
        return self.parent.get_ast_child_node(self.parent.get_ast_child_node(node))[NODE_CODE]

    def get_ast_prop_code(self, node: py2neo.Node) -> str:
        assert node[NODE_TYPE] == TYPE_PROP
        attribute = _normalize(self.parent.get_ast_ith_child_node(node, -1)[NODE_CODE])
        clazz = self.parent.get_ast_child_node(self.parent.get_ast_ith_child_node(node, 0))[NODE_CODE]
        return f"${clazz}->{attribute}"

    def get_ast_static_prop_code(self, node: py2neo.Node) -> str:
        assert node[NODE_TYPE] == TYPE_STATIC_PROP
        attribute = _normalize(self.parent.get_ast_ith_child_node(node, -1)[NODE_CODE])
        clazz = self.parent.get_ast_child_node(self.parent.get_ast_ith_child_node(node, 0))[NODE_CODE]
        return f"{clazz}::${attribute}"

    def get_ast_dim_body_code(self, node: py2neo.Node) -> str:
        assert node[NODE_TYPE] == TYPE_DIM
        dim_body = self.parent.get_ast_node_code(self.parent.get_ast_ith_child_node(node, 0))
        return dim_body

    def get_ast_dim_code(self, node: py2neo.Node) -> str:
        assert node[NODE_TYPE] == TYPE_DIM
        dim_body = self.parent.get_ast_node_code(self.parent.get_ast_ith_child_node(node, 0))
        dim_slice = self.parent.get_ast_node_code(self.parent.get_ast_ith_child_node(node, 1))
        if dim_slice == 'null':
            dim_slice = ''
        elif self.parent.get_ast_ith_child_node(node, 1)[NODE_TYPE] == TYPE_STRING:
            dim_slice = f"\"{dim_slice}\""
        return f"{dim_body}[{dim_slice}]"

    def get_ast_call_code(self, node: py2neo.Node) -> str:
        assert node[NODE_TYPE] == TYPE_CALL
        code = self.parent.get_ast_child_node(self.parent.get_ast_child_node(node))[NODE_CODE]
        # 去除函数名周围的引号（如果有）
        if code:
            code = code.strip('"').strip("'")
        return code

    def get_ast_static_call_code(self, node: py2neo.Node) -> str:
        assert node[NODE_TYPE] == TYPE_STATIC_CALL
        ch_nodes = self.parent.find_ast_child_nodes(node)
        class_name_expr = self.parent.get_ast_child_node(ch_nodes[0])[NODE_CODE]
        if ch_nodes.__len__() >= 1:
            class_method_expr = ch_nodes[1][NODE_CODE]
        else:
            class_method_expr = "$" + self.parent.get_ast_child_node(self.parent.get_ast_ith_child_node(node, 1))[
                NODE_CODE]
        return f"{class_name_expr}::{class_method_expr}"

    def get_ast_class_const_code(self, node: py2neo.Node) -> str:
        assert node[NODE_TYPE] == TYPE_CLASS_CONST
        ch_nodes = self.parent.find_ast_child_nodes(node)
        class_name_expr = self.parent.get_ast_child_node(ch_nodes[0])[NODE_CODE]
        if ch_nodes.__len__() >= 1:
            class_method_expr = ch_nodes[1][NODE_CODE]
        else:
            class_method_expr = "$" + self.parent.get_ast_child_node(self.parent.get_ast_ith_child_node(node, 1))[
                NODE_CODE]
        return f"{class_name_expr}::{class_method_expr}"

    def get_ast_method_call_code(self, node: py2neo.Node) -> str:
        assert node[NODE_TYPE] == TYPE_METHOD_CALL
        if self.parent.get_ast_ith_child_node(node, 1)[NODE_TYPE] == TYPE_VAR:
            return self.parent.get_ast_ith_child_node(self.parent.get_ast_ith_child_node(node, 1), 0)[NODE_CODE]
        return self.parent.get_ast_ith_child_node(node, 1)[NODE_CODE]

    def find_variables(self, _node: py2neo.Node, target_type: Union[List, Set] = None) -> List[str]:
        if _node[NODE_TYPE] in {TYPE_FOREACH}:
            _node = self.parent.ast_step.get_ith_child_node(_node, 0)
        if target_type is None:
            target_type = VAR_TYPES
            result = self.parent.filter_ast_child_nodes(_node=_node, node_type_filter=target_type)
            _res = [_ for _ in map(self.get_node_code, result)]
            return _res
        else:
            result = self.parent.filter_ast_child_nodes(_node=_node, node_type_filter=target_type)
            return list(set(_ for _ in map(self.get_node_code, result)))


def match_best_similar_str_index(org_str: str, given: List[str], method=Levenshtein.jaro) -> int:
    score_vector = [method(org_str, i) for i in given]
    return score_vector.index(max(score_vector))


class FIGStep(AbstractStep):
    def __init__(self, parent):
        super().__init__(parent, "fig_step")

    def get_filesystem_node(self, _node: py2neo.Node) -> py2neo.Node:
        return self.parent.basic_step.match_first(LABEL_FILESYSTEM,
                                                  **{NODE_TYPE: "File", NODE_INDEX: _node[NODE_FILEID]})

    def find_include_src(self, _node: py2neo.Node) -> List[py2neo.Node]:
        res = [i.start_node for i in
               self.parent.neo4j_graph.relationships.match(nodes=[None, _node], r_type=INCLUDE_EDGE, )]
        return list(sorted(res, key=lambda x: x[NODE_INDEX]))

    def find_include_dst(self, _node: py2neo.Node) -> List[py2neo.Node]:
        return [i.end_node for i in
                self.parent.neo4j_graph.relationships.match(nodes=[_node, None], r_type=INCLUDE_EDGE, )]

    def get_include_map(self, _node: py2neo.Node) -> nx.DiGraph:
        return_map = nx.DiGraph()
        return_map.add_node(_node.identity, **_node)
        queue: deque[py2neo.Node] = deque()
        queue.append(_node)
        while queue.__len__() != 0:
            current_node = queue.popleft()
            for node in self.parent.find_fig_include_dst(current_node):
                return_map.add_node(node.identity, **_node)
                return_map.add_edge(current_node.identity, node.identity)
                queue.append(node)
        return return_map

    def get_belong_file(self, _node: py2neo.Node) -> str:
        # 缓存：同一个 fileid 只查一次数据库
        if not hasattr(self, '_file_cache'):
            self._file_cache = {}
        
        file_id = _node[NODE_FILEID]
        # 对于 fileid 为 null 的节点，用节点自身 id 作为缓存 key
        cache_key = file_id if file_id is not None else f"node_{_node[NODE_INDEX]}"
        if cache_key in self._file_cache:
            return self._file_cache[cache_key]
        
        result = self._get_belong_file_uncached(_node)
        self._file_cache[cache_key] = result
        return result

    def _get_belong_file_uncached(self, _node: py2neo.Node) -> str:
        # 优先：通过 fileid 查 Filesystem 节点
        file_id = _node[NODE_FILEID]
        if file_id is not None:
            file_system_node = self.parent.match(LABEL_FILESYSTEM, id=file_id).first()
            if file_system_node is None:
                # 字符串 id fallback
                results = list(self.parent.run(
                    f"MATCH (fs:Filesystem) WHERE toString(fs.id) = '{file_id}' RETURN fs"
                ))
                if results:
                    file_system_node = results[0][0]
            if file_system_node is not None:
                ast_file_node = self.get_node_from_file_system(file_system_node)
                if ast_file_node is not None:
                    return ast_file_node[NODE_NAME]
        # Fallback: 通过 fileid 直接找 AST_TOPLEVEL 文件节点
        # 只匹配 name 包含路径分隔符 / 的（排除类定义的 TOPLEVEL，其 name 是类名）
        if file_id is not None:
            results = list(self.parent.run(
                f"MATCH (toplevel:AST) "
                f"WHERE toplevel.type = '{TYPE_TOPLEVEL}' "
                f"AND toplevel.id = '{file_id}' "
                f"AND toplevel.name IS NOT NULL "
                f"AND toplevel.name CONTAINS '/' "
                f"RETURN toplevel.name LIMIT 1"
            ))
            if results:
                return results[0][0]
            # 如果 fileid 指向的是类 toplevel（name 不含 /），递归查其 fileid
            results = list(self.parent.run(
                f"MATCH (class_top:AST) "
                f"WHERE class_top.id = '{file_id}' "
                f"AND class_top.type = '{TYPE_TOPLEVEL}' "
                f"AND class_top.fileid IS NOT NULL "
                f"RETURN class_top.fileid LIMIT 1"
            ))
            if results:
                parent_fileid = results[0][0]
                if parent_fileid and parent_fileid != file_id:
                    # 用父级 fileid 再查一次文件 toplevel
                    results2 = list(self.parent.run(
                        f"MATCH (file_top:AST) "
                        f"WHERE file_top.type = '{TYPE_TOPLEVEL}' "
                        f"AND file_top.id = '{parent_fileid}' "
                        f"AND file_top.name IS NOT NULL "
                        f"AND file_top.name CONTAINS '/' "
                        f"RETURN file_top.name LIMIT 1"
                    ))
                    if results2:
                        return results2[0][0]
        # 通过 funcid 链找到所属文件
        node_funcid = _node.get(NODE_FUNCID)
        if node_funcid is not None and node_funcid != file_id:
            results = list(self.parent.run(
                f"MATCH (toplevel:AST) "
                f"WHERE toplevel.type = '{TYPE_TOPLEVEL}' "
                f"AND toplevel.id = '{node_funcid}' "
                f"AND toplevel.name IS NOT NULL "
                f"AND toplevel.name CONTAINS '/' "
                f"RETURN toplevel.name LIMIT 1"
            ))
            if results:
                return results[0][0]
            # funcid 也可能指向类 toplevel，再递归一层
            results = list(self.parent.run(
                f"MATCH (class_top:AST) "
                f"WHERE class_top.id = '{node_funcid}' "
                f"AND class_top.type = '{TYPE_TOPLEVEL}' "
                f"AND class_top.fileid IS NOT NULL "
                f"RETURN class_top.fileid LIMIT 1"
            ))
            if results:
                parent_fileid = results[0][0]
                if parent_fileid:
                    results2 = list(self.parent.run(
                        f"MATCH (file_top:AST) "
                        f"WHERE file_top.type = '{TYPE_TOPLEVEL}' "
                        f"AND file_top.id = '{parent_fileid}' "
                        f"AND file_top.name IS NOT NULL "
                        f"AND file_top.name CONTAINS '/' "
                        f"RETURN file_top.name LIMIT 1"
                    ))
                    if results2:
                        return results2[0][0]
        # 最后手段：fileid 和 funcid 都是 null 的情况
        # 通过 PARENT_OF 关系向上找（只找3层，性能可控）
        node_id = _node[NODE_INDEX]
        if node_id is not None:
            results = list(self.parent.run(
                f"MATCH (parent:AST)-[:PARENT_OF*1..3]->(n:AST) "
                f"WHERE n.id = '{node_id}' "
                f"AND parent.type = '{TYPE_TOPLEVEL}' "
                f"AND parent.name IS NOT NULL "
                f"AND parent.name CONTAINS '/' "
                f"RETURN parent.name LIMIT 1"
            ))
            if results:
                return results[0][0]
            # 如果3层找不到，再往上找（类方法可能嵌套更深）
            results = list(self.parent.run(
                f"MATCH (parent:AST)-[:PARENT_OF*1..8]->(n:AST) "
                f"WHERE n.id = '{node_id}' "
                f"AND parent.type = '{TYPE_TOPLEVEL}' "
                f"AND parent.name IS NOT NULL "
                f"AND parent.name CONTAINS '/' "
                f"RETURN parent.name LIMIT 1"
            ))
            if results:
                return results[0][0]
        # 都找不到时返回空字符串
        return ""

    def get_file_name_node(self, _file_name: str, match_strategy=1) -> Union[py2neo.Node, None]:
        if match_strategy == 1:
            nodes = [i for i in
                     self.parent.match("AST", ).where(
                             f"_.type='{TYPE_TOPLEVEL}' and   _.name CONTAINS '{_file_name}' ")]
            if nodes.__len__() >= 1:
                best_index = match_best_similar_str_index(_file_name, [i[NODE_NAME] for i in nodes])
                return nodes[best_index]
            else:
                return None
        elif match_strategy == 0:
            return self.parent.match(LABEL_AST, ).where(f"_.type='{TYPE_TOPLEVEL}' and '{_file_name}' =  _.name").limit(
                    1).first()

    def get_node_from_file_system(self, _node: py2neo.Node) -> py2neo.Node:
        r = self.parent.neo4j_graph.relationships.match(nodes=[_node], r_type=FILE_EDGE).first()
        if r is None:
            results = list(self.parent.run(
                f"MATCH (fs:Filesystem) - [:FILE_OF] -> (f:AST) WHERE toString(fs.id) = '{_node[NODE_INDEX]}' RETURN f"
            ))
            if not results:
                return None
            return results[0][0]
        else:
            return r.end_node

    def get_toplevel_file_first_statement(self, toplevel_file_node):
        assert toplevel_file_node[NODE_TYPE] in {TYPE_TOPLEVEL} and \
               NODE_FLAGS in toplevel_file_node.keys() and \
               set(toplevel_file_node[NODE_FLAGS]) & {FLAG_TOPLEVEL_FILE}
        stmt = self.parent.get_ast_child_node(toplevel_file_node)
        return self.parent.get_ast_child_node(stmt)

    def get_top_filesystem_node(self, _node: py2neo.Node) -> py2neo.Node:
        return self.parent.match_first(LABEL_FILESYSTEM, **{NODE_TYPE: "File", NODE_INDEX: _node[NODE_FILEID]})


class PDGStep(AbstractStep):
    def __init__(self, parent):
        super().__init__(parent, "pdg_step")

    def find_use_nodes(self, _node: py2neo.Node) -> List[py2neo.Node]:
        res = [i.end_node for i in
               self.parent.neo4j_graph.relationships.match(nodes=[_node, None], r_type=DATA_FLOW_EDGE, )]
        return list(sorted([i for i in res if i is not None], key=lambda x: x[NODE_INDEX]))

    def find_def_nodes(self, _node: py2neo.Node, _var=None) -> List[py2neo.Node]:
        if _var is None:
            res = [i.start_node for i in
                   self.parent.neo4j_graph.relationships.match(nodes=[None, _node], r_type=DATA_FLOW_EDGE, )]
        else:
            res = [i.start_node for i in
                   self.parent.neo4j_graph.relationships.match(nodes=[None, _node], r_type=DATA_FLOW_EDGE, var=_var)]

        return list(sorted(res, key=lambda x: x[NODE_INDEX]))

    def get_related_vars(self, _node_start: py2neo.Node, _node_end: py2neo.Node) -> List[str]:
        return [i.get(DATA_FLOW_SYMBOL) for i in
                self.parent.neo4j_graph.relationships.match(nodes=[_node_start, _node_end], r_type=CALLS_EDGE, )]
    
    def is_tracable(self, _obj_ast: py2neo.Node):
        if _obj_ast[NODE_TYPE] in {TYPE_CALL, TYPE_STATIC_CALL, TYPE_METHOD_CALL, TYPE_NEW}:
            arg_list_node = self.parent.ast_step.find_child_nodes(_obj_ast, include_type=[TYPE_ARG_LIST])[0]
            if not self.parent.code_step.find_variables(arg_list_node, VAR_TYPES_EXCLUDE_CONST_VAR):
                return False
        
        TRACABLE_FLAG = True
        vars = self.parent.code_step.find_variables(_obj_ast)
        if vars.__len__() >= 1:
            def_nodes = self.find_def_nodes(_obj_ast)
            bad_flag = 0
            lock = 0
            for def_node in def_nodes:
                if def_node[NODE_TYPE] in {TYPE_ASSIGN, TYPE_ASSIGN_REF}:
                    src_var = self.parent.code_step.get_node_code(self.parent.ast_step.get_ith_child_node(def_node, 0))
                    if src_var in vars:
                        if self.parent.ast_step.get_ith_child_node(def_node, 1)[NODE_TYPE] in COMMON_VAR_TYPES:
                            if not (lock & ((1 << (vars.index(src_var))))):
                                bad_flag |= (1 << (vars.index(src_var)))
                        else:
                            bad_flag &= ((1 << vars.__len__()) - 1) ^ (1 << (vars.index(src_var)))
                            lock |= (1 << (vars.index(src_var)))
            if bad_flag == (1 << vars.__len__()) - 1:
                TRACABLE_FLAG = False
        else:
            TRACABLE_FLAG = False
        return TRACABLE_FLAG


class RangeStep(AbstractStep):
    def __init__(self, parent):
        super().__init__(parent, "range_step")
        self.__range_cache = {}

    def get_general_node_range(self, node: py2neo.Node, use_cache=True) -> Tuple[int, int]:
        parent_node = self.parent.ast_step.get_parent_node(node, ignore_error_flag=True)
        node_hash = f"{self.get_general_node_range.__name__}{node.identity.__str__()} "
        if node_hash not in self.__range_cache.keys():
            if node[NODE_TYPE] in {TYPE_FOREACH}:
                end_id = self.parent.cfg_step.find_successors(node)[-1][NODE_INDEX]
                if end_id > node[NODE_INDEX]:
                    node_range = (node[NODE_INDEX], end_id)
                    self.__range_cache[node_hash] = node_range
                else:
                    raise NotImplementedError()
            elif node[NODE_TYPE] in {TYPE_WHILE}:
                pass
                raise NotImplementedError()
            elif parent_node is not None and parent_node[NODE_TYPE] in {TYPE_IF_ELEM}:
                if self.parent.cfg_step.find_successors(node).__len__() == 0:
                    logger.fatal(f"no flows to another node for control node {node}")
                    node_range = (parent_node[NODE_INDEX], parent_node[NODE_INDEX] + 500)
                else:
                    node_range = (
                            parent_node[NODE_INDEX], self.parent.cfg_step.find_successors(node)[-1][NODE_INDEX] - 1)
                self.__range_cache[node_hash] = node_range
            else:
                reg_function = [i for i in self.__dir__() if not i.__str__().startswith("_")]
                if "get_{}_node_range".format(node[NODE_TYPE].lower()) not in reg_function:
                    node_range = (node[NODE_INDEX], self.parent.ast_step.filter_child_nodes(node)[-1][NODE_INDEX])
                else:
                    node_range = eval("self.get_{}_node_range(node)".format(node[NODE_TYPE].lower()))
                self.__range_cache[node_hash] = node_range
        return self.__range_cache[node_hash]

    def get_condition_range(self, node: py2neo.Node) -> Tuple[int, int]:
        if node[NODE_TYPE] not in [TYPE_IF_ELEM]:
            return (-1, -1)
        stmt_list_node = self.parent.ast_step.get_ith_child_node(node, 1)
        if self.parent.ast_step.find_child_nodes(stmt_list_node):
            last_stmt_node = self.parent.ast_step.find_child_nodes(stmt_list_node)[-1]
            return (node[NODE_INDEX], last_stmt_node[NODE_INDEX])
        else:
            return (node[NODE_INDEX], node[NODE_INDEX])

    def get_ast_func_decl_range(self, node: py2neo.Node) -> Tuple[int, int]:
        assert node[NODE_TYPE] == TYPE_FUNC_DECL
        RR = self.parent.basic_step.match_first(LABEL_AST,
                                                **{NODE_FILEID: node[NODE_FILEID], NODE_LINENO: node[NODE_ENDLINENO]})
        if not RR:
            RR = self.parent.basic_step.match_first(LABEL_AST, **{NODE_FILEID: node[NODE_FILEID],
                                                                  NODE_LINENO: node[NODE_ENDLINENO] - 1})
        if not RR:
            logger.fatal("endlineno is wrong or need enhancement")
        end_line_root_node = self.parent.ast_step.get_root_node(RR)
        last_node = self.parent.ast_step.find_child_nodes(end_line_root_node)[-1]
        return node[NODE_INDEX], last_node[NODE_INDEX]

    def get_ast_method_range(self, node: py2neo.Node) -> Tuple[int, int]:
        assert node[NODE_TYPE] == TYPE_METHOD
        RR = self.parent.basic_step.match_first(LABEL_AST,
                                                **{NODE_FILEID: node[NODE_FILEID], NODE_LINENO: node[NODE_ENDLINENO]})
        if not RR:
            RR = self.parent.basic_step.match_first(LABEL_AST, **{NODE_FILEID: node[NODE_FILEID],
                                                                  NODE_LINENO: node[NODE_ENDLINENO] - 1})
        if not RR:
            logger.fatal("endlineno is wrong or need enhancement")
        end_line_root_node = self.parent.ast_step.get_root_node(RR)
        last_node = self.parent.ast_step.filter_child_nodes(end_line_root_node)[-1]
        return node[NODE_INDEX], last_node[NODE_INDEX]

