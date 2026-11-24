import json
import os
import re
import subprocess
from collections import defaultdict
from typing import NamedTuple

from core.neo4j_engine.const import TYPE_METHOD_CALL, TYPE_STATIC_CALL, php_symbol_key


class Token(NamedTuple):
    kind: str
    text: str
    start: int
    end: int
    line: int


def php_tokens(code, first_line, fragment):
    """Get source positions from PHP's lexer, treating literals as opaque."""
    result = subprocess.run(
        [os.environ.get('PHP7', 'php'), '-r', '''
            $code = stream_get_contents(STDIN);
            $tokens = token_get_all($argc > 1 ? '<?php ' . $code : $code);
            if ($argc > 1) { array_shift($tokens); }
            echo json_encode(array_map(function ($token) {
                return is_array($token) ? [token_name($token[0]), $token[1]] : $token;
            }, $tokens));
        ''', '--', *(['fragment'] if fragment else [])],
        input=code, text=True, encoding='utf-8', capture_output=True, check=True,
    )
    offset = 0
    line = first_line
    literal = None
    braces = 0
    for raw in json.loads(result.stdout):
        kind, text = raw[:2] if isinstance(raw, list) else (raw, raw)
        token = Token(kind, text, offset, offset + len(text), line)
        offset = token.end
        line += text.count('\n')
        if literal:
            if kind == literal[0] and not braces:
                start = literal[1]
                yield Token('literal', code[start.start:offset], start.start, offset, start.line)
                literal = None
            elif kind in {'T_CURLY_OPEN', 'T_DOLLAR_OPEN_CURLY_BRACES', '{'}:
                braces += 1
            elif kind == '}' and braces:
                braces -= 1
        elif kind in {'"', '`', 'T_START_HEREDOC'}:
            literal = ('T_END_HEREDOC' if kind == 'T_START_HEREDOC' else kind, token)
        else:
            yield token
    if literal:
        start = literal[1]
        yield Token('literal', code[start.start:], start.start, len(code), start.line)


TRIVIA = {'T_WHITESPACE', 'T_COMMENT', 'T_DOC_COMMENT'}
IDENTIFIER = re.compile(r'[a-zA-Z_\x80-\U0010ffff][a-zA-Z_0-9\x80-\U0010ffff]*\Z')
MEMBER_OPERATORS = {'T_OBJECT_OPERATOR': TYPE_METHOD_CALL, 'T_DOUBLE_COLON': TYPE_STATIC_CALL}
METHOD_MODIFIERS = {'T_PUBLIC', 'T_PROTECTED', 'T_PRIVATE', 'T_STATIC', 'T_FINAL', 'T_ABSTRACT'}
CLOSING_BRACKETS = {')': '(', ']': '[', '}': '{'}


class PhpSource:
    def __init__(self, code, first_line=1, *, fragment=True):
        self.code = code
        all_tokens = list(php_tokens(code, first_line, fragment))
        self.tokens = [token for token in all_tokens if token.kind not in TRIVIA]
        self.comments = [token for token in all_tokens if token.kind in {'T_COMMENT', 'T_DOC_COMMENT'}]
        self.pairs = {}
        brackets = []
        for index, token in enumerate(self.tokens):
            if token.kind in {'(', '[', '{'}:
                brackets.append(index)
            elif brackets and CLOSING_BRACKETS.get(token.kind) == self.tokens[brackets[-1]].kind:
                start = brackets.pop()
                self.pairs[start] = index
                self.pairs[index] = start

    def declarations(self, name, first_line, last_line):
        """Locate declarations inside the AST's source line range."""
        tokens = self.tokens
        for index, token in enumerate(tokens[:-2]):
            if token.kind != 'T_FUNCTION' or not first_line <= token.line <= last_line:
                continue
            name_index = index + (2 if tokens[index + 1].text == '&' else 1)
            if php_symbol_key(tokens[name_index].text) != php_symbol_key(name):
                continue
            args_end = self.pairs.get(name_index + 1, len(tokens))
            for body in range(args_end + 1, len(tokens)):
                if tokens[body].kind == ';':
                    break
                if tokens[body].kind == '{':
                    end = self.pairs.get(body)
                    if end is not None and tokens[end].line == last_line:
                        yield index, name_index, end
                    break

    def declaration_owner(self, function_index):
        """Find the enclosing named class for same-line declarations."""
        for index in range(function_index - 1, -1, -1):
            token, name = self.tokens[index:index + 2]
            if token.kind not in {'T_CLASS', 'T_TRAIT', 'T_INTERFACE'} or name.kind != 'T_STRING':
                continue
            for opening in range(index + 2, function_index):
                if self.tokens[opening].kind == '{':
                    if self.pairs.get(opening, 0) > function_index:
                        return php_symbol_key(name.text)
                    break
        return None

    def declaration_bounds(self, first, last):
        start, end = self.tokens[first].start, self.tokens[last].end
        previous_end = self.tokens[first - 1].end if first else 0
        next_start = self.tokens[last + 1].start if last + 1 < len(self.tokens) else len(self.code)
        for comment in self.comments:
            if previous_end <= comment.start < start and comment.line == self.tokens[first].line:
                start = comment.start
            if end <= comment.start < next_start and comment.line == self.tokens[last].line:
                end = comment.end
        return start, end

    def receiver_start(self, index):
        tokens = self.tokens
        start = index
        while start >= 0:
            token = tokens[start]
            if token.kind in {')', ']'} and start in self.pairs:
                start = self.pairs[start]
                if start and self.is_call_head(tokens[start - 1]):
                    start -= 1
                    continue
            while start > 0 and tokens[start - 1].kind == 'T_NS_SEPARATOR':
                start -= 1
                if start and tokens[start - 1].kind == 'T_STRING':
                    start -= 1
            if start > 1 and tokens[start - 1].kind in MEMBER_OPERATORS:
                start -= 2
                continue
            if start and tokens[start - 1].kind == 'T_NEW':
                start -= 1
            break
        return start

    @staticmethod
    def is_call_head(token):
        return token.kind in {'T_STRING', 'T_VARIABLE', 'T_NAME_QUALIFIED', 'T_NAME_FULLY_QUALIFIED', ')', ']'}

    def member_edits(self, first, last, bindings):
        # phpjoern allocates IDs in preorder. The method-name child comes after
        # the receiver subtree, so its ID orders chained calls by name position.
        calls = defaultdict(list)
        for call_type, name, name_id, line, symbol in bindings:
            calls[call_type, php_symbol_key(name) if name is not None else None].append(
                (int(name_id), int(line), symbol)
            )
        sites = defaultdict(list)
        for index in range(first + 1, last - 1):
            operator, name = self.tokens[index:index + 2]
            if operator.kind not in MEMBER_OPERATORS:
                continue
            name_end = self.pairs.get(index + 1, index + 1) if name.kind == '{' else index + 1
            if name_end + 1 >= last or self.tokens[name_end + 1].kind != '(':
                continue
            if IDENTIFIER.fullmatch(name.text):
                key = php_symbol_key(name.text)
            elif name.kind in {'T_VARIABLE', '{'}:
                key = None
            else:
                continue
            start = self.tokens[self.receiver_start(index - 1)]
            sites[MEMBER_OPERATORS[operator.kind], key].append((start, self.tokens[name_end]))
        for key, positions in sites.items():
            candidates = sorted(calls[key])
            if len(positions) == len(candidates):
                for (start, name), (_, line, symbol) in zip(positions, candidates):
                    if start.line <= line <= name.line:
                        yield start.start, name.end, self.keep_comments(start.start, name.end) + symbol

    def keep_comments(self, start, end):
        return ''.join(token.text + ('\n' if token.text.startswith(('//', '#')) else ' ')
                       for token in self.comments if start <= token.start < end)

    def normalization_edits(self, temporary_var=None, first=0, last=None):
        """Apply the existing property and PHP-version normalization to code tokens."""
        tokens = self.tokens
        for index in range(first, len(tokens) if last is None else last):
            token = tokens[index]
            following = tokens[index + 1:index + 3]
            if token.kind in MEMBER_OPERATORS and index and following:
                name = following[0]
                if len(following) == 2 and following[1].kind == '(':
                    continue
                if token.kind == 'T_OBJECT_OPERATOR' and IDENTIFIER.fullmatch(name.text):
                    replacement = '$' + name.text
                elif token.kind == 'T_DOUBLE_COLON' and temporary_var and (
                    IDENTIFIER.fullmatch(name.text) or name.kind == 'T_VARIABLE'
                ):
                    replacement = temporary_var()
                else:
                    continue
                start = tokens[self.receiver_start(index - 1)].start
                yield start, name.end, self.keep_comments(start, name.end) + replacement
            elif temporary_var and token.kind == 'T_VARIABLE' and token.text == '$this':
                yield token.start, token.end, temporary_var()
            elif temporary_var and token.kind == 'T_STRING' and php_symbol_key(token.text) == 'mixed':
                if following and following[0].kind == 'T_VARIABLE':
                    yield token.start, token.end, ''

    def render(self, edits, start=0, end=None):
        # An outer call or property replacement consumes its receiver, including
        # any edits inside that receiver. Apply the widest edit at each position.
        parts = []
        for left, right, replacement in sorted(edits, key=lambda edit: (edit[0], -edit[1])):
            if left < start or (end is not None and right > end):
                continue
            parts.extend((self.code[start:left], replacement))
            start = right
        parts.append(self.code[start:end])
        return ''.join(parts)
