import csv
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from collections import defaultdict
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import py2neo

import PUT_extractor
from core.neo4j_engine.const import (
    FLAG_BINARY_BOOL_AND, TYPE_BINARY_OP, TYPE_CALL, TYPE_ECHO, TYPE_FUNC_DECL,
    TYPE_METHOD, TYPE_METHOD_CALL, TYPE_STATIC_CALL, php_symbol_key,
)
from core.neo4j_engine.steps import ASTStep, CGStep, CodeStep


PHP = os.environ.get('PHP7', 'php')
TEST_DIR = Path(__file__).resolve().parent
PARSER = TEST_DIR.parents[2] / 'phpjoern' / 'src' / 'Parser.php'


class FixtureGraph:
    """Use phpjoern's real AST and supply only the graph storage operations."""

    def __init__(self, directory, source):
        self.source = str(source)
        with (directory / 'nodes.csv').open() as file:
            rows = csv.DictReader(file, delimiter='\t', escapechar='\\')
            self.nodes = {}
            for row in rows:
                props = {key.split(':')[0]: value for key, value in row.items() if value}
                if 'flags' in props:
                    props['flags'] = props['flags'].split(',')
                node_id = int(props.pop('id'))
                node = py2neo.Node(props.pop('labels'), id=str(node_id), **props)
                node.identity = node_id
                self.nodes[str(node_id)] = node
        self.children = defaultdict(list)
        with (directory / 'rels.csv').open() as file:
            for edge in csv.DictReader(file, delimiter='\t'):
                if edge['type'] == 'PARENT_OF':
                    self.children[edge['start']].append(self.nodes[edge['end']])
        self.edges = defaultdict(list)
        self.ast_step = ASTStep(self)
        self.ast_step.find_child_nodes = self.find_ast_child_nodes
        self.ast_step.find_sources = lambda _: []
        self.cg_step = CGStep(self)
        self.cg_step.find_decl_nodes = lambda call: self.edges[call['id']]
        self.code_step = CodeStep(self)
        self.basic_step = SimpleNamespace(run=self.lookup)
        self.fig_step = SimpleNamespace(get_belong_file=lambda _: self.source)

    def get_node_itself(self, node_id):
        return self.nodes[str(node_id)]

    def find_ast_child_nodes(self, node, include_type=None):
        return [child for child in self.children[node['id']]
                if include_type is None or child['type'] in include_type]

    def get_ast_child_node(self, node, ignore_error_flag=False):
        return self.ast_step.get_ith_child_node(node, 0, ignore_error_flag)

    def get_ast_ith_child_node(self, node, index):
        return self.ast_step.get_ith_child_node(node, index)

    def filter_ast_child_nodes(self, node, node_type_filter):
        found = [node] if node['type'] in node_type_filter else []
        for child in self.find_ast_child_nodes(node):
            found.extend(self.filter_ast_child_nodes(child, node_type_filter))
        return found

    def lookup(self, query, parameters=None):
        # Apply the storage predicates and retain the real CGStep's AST checks.
        if parameters is None:
            return [(node['name'],) for node in self.nodes.values() if node['type'] == TYPE_FUNC_DECL]
        result = []
        for node in self.nodes.values():
            if node['type'] != parameters['type'] or php_symbol_key(node['name']) != parameters['name']:
                continue
            owner = parameters.get('owner')
            if owner and php_symbol_key(node['classname']) != owner:
                continue
            result.append((node, node['name']))
        return result

    def declaration(self, name, owner=None):
        return next(node for node in self.nodes.values()
                    if node['type'] in {TYPE_FUNC_DECL, TYPE_METHOD}
                    and node['name'] == name and node['classname'] == owner)

    def call(self, kind, name, owner=None):
        return next(node for node in self.nodes.values()
                    if node['type'] == kind and node['classname'] == owner
                    and self.cg_step.get_call_name_node(node)['code'] == name)

    def entry_nodes(self):
        return [int(node['id']) for node in self.nodes.values() if node['type'] == TYPE_ECHO]


@unittest.skipUnless(shutil.which(PHP), 'Requires the project PHP CLI with php-ast')
class FunctionExtractorTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        fixture = TEST_DIR / 'fixtures' / 'symbols.php'
        subprocess.run([PHP, PARSER, fixture], cwd=self.directory, text=True, capture_output=True, check=True)
        self.graph = FixtureGraph(self.directory, fixture)
        storage = self.directory / 'storage'
        for target, value in [
            ('core.function_extractor.STORAGE_PATH', str(storage)),
            ('PUT_extractor.PUT_STORAGE_PATH', str(storage / 'PUT')),
        ]:
            patcher = patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.output = storage / 'PUT' / 'fixture' / '1'

    def generate(self, entry_nodes=None):
        steps = {
            'Neo4jEngine.from_dict': self.graph,
            'Neo4jConnectorCenter.from_map': {},
            'load_taint_flow': [self.graph.entry_nodes() if entry_nodes is None else entry_nodes],
            'sink_context_analysis': ('', ''),
        }
        with ExitStack() as stack:
            for name, result in steps.items():
                stack.enter_context(patch(f'PUT_extractor.{name}', return_value=result))
            PUT_extractor.run('fixture')
        for file in ('index.php', 'function_definition.php'):
            lint = subprocess.run([PHP, '-l', file], cwd=self.output, text=True, capture_output=True)
            self.assertEqual(lint.returncode, 0, lint.stdout + lint.stderr)
        return (self.output / 'index.php').read_text(), (self.output / 'function_definition.php').read_text()

    def test_header_wrapper_and_shared_index_bindings(self):
        index, definitions = self.generate()
        header = self.graph.declaration('header', 'UploadHandler')
        query = self.graph.declaration('query', 'UploadHandler')
        send = self.graph.declaration('send', 'UploadHandler')
        deeper = self.graph.declaration('formatLabel', 'UploadHandler')
        for node in (header, query, send):
            symbol = f"__put_method_{node['id']}"
            self.assertIn(f'function {symbol}(', definitions)
            self.assertIn(f'{symbol}(', index)
        self.assertIn('header($str);', definitions)
        self.assertIn('HeAdEr($str);', definitions)
        self.assertIn(f"/* receiver comment */ __put_method_{query['id']}()", definitions)
        self.assertIn(f"__put_method_{send['id']}('')", definitions)
        self.assertIn(f"function __put_method_{deeper['id']}() {{ return func_num_args()", definitions)
        self.assertNotIn('deeper definition', definitions)
        self.assertNotRegex(definitions, r'(?i)function\s+header\s*\(')
        for text in (
            "// $this->query() UploadHandler::send() pretend_call()",
            "} // $this->query()",
            "'$this->query() UploadHandler::send() pretend_call()'",
            '"UploadHandler::send() pretend_call()"',
            "<<<'TEXT'\n$this->query() UploadHandler::send() pretend_call()\nTEXT;",
        ):
            self.assertIn(text, definitions)
        self.assertNotIn('function pretend_call(', definitions)

    def test_mixed_case_and_wrong_edge_types(self):
        instance = self.graph.declaration('query', 'UploadHandler')
        global_query = self.graph.declaration('query')
        self.graph.edges[self.graph.call(TYPE_CALL, 'QuErY')['id']] = [instance]
        self.graph.edges[self.graph.call(TYPE_METHOD_CALL, 'qUeRy')['id']] = [global_query, instance]
        self.graph.edges[self.graph.call(TYPE_STATIC_CALL, 'sEnD')['id']] = [self.graph.declaration('send')]
        self.generate()
        actual = subprocess.run([PHP, 'index.php'], cwd=self.output, text=True, capture_output=True, check=True)
        self.assertEqual(actual.stderr, '')
        self.assertEqual(
            actual.stdout,
            'instancestaticglobalinstancestaticglobal-sendunresolved-sendunresolved-header',
        )

    def test_ambiguous_and_unowned_members_get_separate_stubs(self):
        call = self.graph.call(TYPE_METHOD_CALL, 'sEND', 'UploadHandler')
        self.assertEqual(self.graph.cg_step.match_decl_nodes(call), [])
        self.graph.edges[call['id']] = [
            self.graph.declaration('send', 'UploadHandler'), self.graph.declaration('send', 'Other'),
        ]
        _, definitions = self.generate()
        for spelling in ('sEND', 'HeAdEr'):
            member = self.graph.call(TYPE_METHOD_CALL, spelling, 'UploadHandler')
            stub = f"__put_member_stub_{member['id']}"
            self.assertIn(f'function {stub}()', definitions)
            self.assertIn(f'return func_num_args() > 0 ? func_get_arg(0) : null;', definitions)
        self.assertEqual(len(re.findall(r'(?i)function send\(', definitions)), 1)

    def test_generated_method_name_avoids_global_declaration(self):
        header = self.graph.declaration('header', 'UploadHandler')
        symbol = f"__put_method_{header['id']}"
        self.graph.nodes['99999'] = py2neo.Node('AST', type=TYPE_FUNC_DECL, name=symbol.upper())
        index, definitions = self.generate()
        self.assertIn(f'{symbol}_(', index)
        self.assertIn(f'function {symbol}_(', definitions)

    def test_comparison_as_output_expression(self):
        comparison = next(node for node in self.graph.nodes.values()
                          if node['type'] == TYPE_BINARY_OP and FLAG_BINARY_BOOL_AND in node['flags'])
        index, _ = self.generate([int(comparison['id'])])
        self.assertIn('echo((("ready" == "ready") && (1 > 0)));', index)
        result = subprocess.run([PHP, 'index.php'], cwd=self.output, text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout, '1')


if __name__ == '__main__':
    unittest.main()
