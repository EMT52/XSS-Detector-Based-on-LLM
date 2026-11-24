import py2neo

from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *

def sink_context_analysis(analyzer: Neo4jEngine, sink_node: py2neo.Node) -> str:
    echo_node_types = [TYPE_ECHO, TYPE_PRINT]
    # 使用 toInteger 把字符串 id 转成整数比较，兼容字符串和整数 id 两种导入方式
    constant_strings = [s for s, in analyzer.run(
        f"MATCH path = (e) - [:PARENT_OF*0..] -> (s) WHERE toString(e.funcid)='{sink_node[NODE_FUNCID]}' "\
        f"AND toInteger(e.id) < toInteger('{sink_node[NODE_INDEX]}') AND e.type IN {echo_node_types.__str__()} "\
        f"AND ALL(n IN nodes(path)[1..-1] WHERE ((n.type='{TYPE_BINARY_OP}' AND n.flags=['{FLAG_BINARY_CONCAT}']) "\
        f"OR n.type='{TYPE_ENCAPS_LIST}')) "\
        f"AND s.type='string' AND s.code IS NOT NULL "\
        "RETURN s.code ORDER BY toInteger(s.id) ASC"
    )]
    constant_strings = [s for s in constant_strings if s]
    predecessor_context = "".join(constant_strings)

    constant_strings = [s for s, in analyzer.run(
        f"MATCH path = (e) - [:PARENT_OF*0..] -> (s) WHERE toString(e.funcid)='{sink_node[NODE_FUNCID]}' "\
        f"AND toInteger(e.id) > toInteger('{sink_node[NODE_INDEX]}') AND e.type IN {echo_node_types.__str__()} "\
        f"AND ALL(n IN nodes(path)[1..-1] WHERE ((n.type='{TYPE_BINARY_OP}' AND n.flags=['{FLAG_BINARY_CONCAT}']) "\
        f"OR n.type='{TYPE_ENCAPS_LIST}')) "\
        f"AND s.type='string' AND s.code IS NOT NULL "\
        "RETURN s.code ORDER BY toInteger(s.id) ASC"
    )]
    constant_strings = [s for s in constant_strings if s]
    successor_context = "".join(constant_strings)
    return (predecessor_context, successor_context)

