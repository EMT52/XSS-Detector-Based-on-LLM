import random
import re
from urllib.parse import quote

def function_mutate(vector, matched_substring):
    all_matches =[]
    if isinstance(matched_substring, str):
        all_matches.append(matched_substring)
    elif isinstance(matched_substring, (list, tuple, set)):
        for substring in matched_substring:
            matches = re.findall(re.escape(substring), vector)
            all_matches.extend(matches)
    else:
        return set()
    
    new_vectors = set()
    randomized_vector = vector
    double_writed_vector = vector
    encode_vector = vector
    urlencode_vector = vector
    unicode_vector = vector
    for match in all_matches:
        randomized_substring = random_case(match)
        double_writed_substring = double_write_substring(match)
        encoded_substring = hex_html_no_semicolon_encode(match)
        url_encoded_substring = url_encode(match)
        unicode_substring = unicode_encode(match)
        randomized_vector = randomized_vector.replace(match, randomized_substring, 1)
        double_writed_vector = double_writed_vector.replace(match, double_writed_substring, 1)
        encode_vector = encode_vector.replace(match, encoded_substring, 1)
        urlencode_vector = urlencode_vector.replace(match, url_encoded_substring, 1)
        unicode_vector = unicode_vector.replace(match, unicode_substring, 1)
    new_vectors.add(randomized_vector)
    new_vectors.add(double_writed_vector)
    new_vectors.add(encode_vector)
    new_vectors.add(urlencode_vector)
    new_vectors.add(unicode_vector)
    return new_vectors

def inline_mutate(vector, matched_substring):
    all_matches =[]
    if isinstance(matched_substring, str):
        all_matches.append(matched_substring)
    elif isinstance(matched_substring, (list, tuple, set)):
        for substring in matched_substring:
            matches = re.findall(re.escape(substring), vector)
            all_matches.extend(matches)
    else:
        return set()
    
    new_vectors = set()
    randomized_vector = vector
    double_writed_vector = vector

    for match in all_matches:
        randomized_substring = random_case(match)
        double_writed_substring = double_write_substring(match)
        randomized_vector = randomized_vector.replace(match, randomized_substring, 1)
        double_writed_vector = double_writed_vector.replace(match, double_writed_substring, 1)
    new_vectors.add(randomized_vector)
    new_vectors.add(double_writed_vector)

    return new_vectors
    
def protocols_mutate(vector, matched_substring):
    all_matches =[]
    if isinstance(matched_substring, str):
        all_matches.append(matched_substring)
    elif isinstance(matched_substring, (list, tuple, set)):
        for substring in matched_substring:
            matches = re.findall(re.escape(substring), vector)
            all_matches.extend(matches)
    else:
        return set()
    
    new_vectors = set()
    randomized_vector = vector
    double_writed_vector = vector
    encode_vector = vector
    for match in all_matches:
        randomized_substring = random_case(match)
        double_writed_substring = double_write_substring(match)
        encode_substring = hex_html_no_semicolon_encode(match)
        randomized_vector = randomized_vector.replace(match, randomized_substring, 1)
        double_writed_vector = double_writed_vector.replace(match, double_writed_substring, 1)
        encode_vector = encode_vector.replace(match, encode_substring, 1)
    new_vectors.add(randomized_vector)
    new_vectors.add(double_writed_vector)
    new_vectors.add(encode_vector)
    
    return new_vectors

def events_mutate(vector, matched_substring):
    all_matches =[]
    if isinstance(matched_substring, str):
        all_matches.append(matched_substring)
    elif isinstance(matched_substring, (list, tuple, set)):
        for substring in matched_substring:
            matches = re.findall(re.escape(substring), vector)
            all_matches.extend(matches)
    else:
        return set()
    
    new_vectors = set()
    randomized_vector = vector
    double_writed_vector = vector
    for match in all_matches:
        randomized_substring = random_case(match)
        double_writed_substring = double_write_substring(match)
        randomized_vector = randomized_vector.replace(match, randomized_substring, 1)
        double_writed_vector = double_writed_vector.replace(match, double_writed_substring, 1)
    new_vectors.add(randomized_vector)
    new_vectors.add(double_writed_vector)
    return new_vectors

def obfuscate_tags(text):
    pattern = re.compile(r'(<\/?)(\w+)(>)')
    
    def add_obfuscation(match):
        start, tagname, end = match.groups()
        obfuscated_tagname = f"{tagname}<scr<script>ipt>"
        return f"{start}{obfuscated_tagname}{end}"
    
    return pattern.sub(add_obfuscation, text)

def double_write_substring(keyword):
    half_length = len(keyword) // 2
    first_half = keyword[:half_length]
    second_half = keyword[half_length:]
    
    result = f"{first_half}{keyword}{second_half}"
    
    return result

def random_case(payload):
    return ''.join(random.choice([c.lower(), c.upper()]) for c in payload)

def space_bypass(payload):
    bypass_payload = payload.replace(' ', '/')
    return bypass_payload

def bracket_bypass(payload):
    bypass_payload = payload.replace('(', '`').replace(')', '`')
    return bypass_payload

def decimal_html_encode(payload):
    decimal_codes = ''.join(f'&#{ord(char)};' for char in payload)
    return decimal_codes
    
def decimal_html_no_semicolon_encode(payload, length = 7):
    encoded_string = ''.join(f'&#{ord(char):0{length}}' for char in payload)
    return encoded_string
    
def hex_html_no_semicolon_encode(payload):
    encoded_string = ''.join(f'&#x{ord(char):X}'for char in payload)
    return encoded_string

def url_encode(payload):
    encoded_string = quote(payload)
    return encoded_string
    
def unicode_encode(payload):
    encoded_string = ''
    inside_brackets = False
    bracket_content = ''

    for char in payload:
        if char == '(':
            inside_brackets = True
            encoded_string += char
        elif char == ')':
            inside_brackets = False
            encoded_string += bracket_content + char
            bracket_content = ''
        elif inside_brackets:
            bracket_content += char
        else:
            encoded_string += f'\\u{ord(char):04X}' if char not in '(\'")' else char

    return encoded_string

def js2html_encode(payload):
    js_encoded = unicode_encode(payload)
    html_encoded = hex_html_no_semicolon_encode(js_encoded)
    return html_encoded
    
def url2html_encode(payload):
    url_encoded = url_encode(payload)
    html_encoded = hex_html_no_semicolon_encode(url_encoded)
    return html_encoded

def js2url_encode(payload):
    js_encoded = unicode_encode(payload)
    url_encoded = url_encode(js_encoded)
    return url_encoded
    
def js2url2html_encode(payload):
    js_encoded = unicode_encode(payload)
    url_encoded = url_encode(js_encoded)
    html_encoded = hex_html_no_semicolon_encode(url_encoded)
    return html_encoded
