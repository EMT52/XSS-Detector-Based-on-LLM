from .evasion_model import bracket_bypass, hex_html_no_semicolon_encode, unicode_encode, js2html_encode, function_mutate, inline_mutate, protocols_mutate, events_mutate
from .config_model import unique_probe, jfillings, functions, feedback_log, feedback_dir, xt_file, script_starttag, script_endtag,protocolsAttributes,eventHandlers,  fillings, protocols
from .helper_model import read_matched_substring, calculate_cosine_similarity,generate_tag, parse_logs, chose_most_similar, input_similarity,extract_tags, get_matched_string, parse_xt_file
import re
import random
from threading import Lock
import threading
from queue import Queue

log_lock = Lock()
class JavaScriptCodeCharacters:
    def __init__(self):
        self.javascriptcode = [
            'alert(1)',
            'prompt(1)',
            'confirm(1)'
        ]

    def stripper(self, string, substring, direction='right'):
        done = False
        strippedString = ''
        if direction == 'right':
            string = string[::-1]
        for char in string:
            if char == substring and not done:
                done = True
            else:
                strippedString += char
        if direction == 'right':
            strippedString = strippedString[::-1]
        return strippedString


    def script_parser(self, script):
        broken = script.split(unique_probe)
        pre = broken[0]
        pre = re.sub(r'(?s)(\{.*?\}|.*?\)|".*?"|\'.*?\')', '', pre)
        breaker = ''
        num = 0
        for char in pre:
            if char == '{':
                breaker += '}'
            elif char == '(':
                breaker += ';)'
            elif char == '[':
                breaker += ']'
            elif char == '/':
                try:
                    if pre[num + 1] == '*':
                        breaker += '/*'
                except IndexError:
                    pass
            elif char == '}':
                breaker = self.stripper(breaker, '}')
            elif char == ')':
                breaker = self.stripper(breaker, ')')
            elif char == ']':
                breaker = self.stripper(breaker, ']')
            num += 1
        return breaker[::-1]
    
    def script_attackgrammar(self, tester, script_context, context, test_put_path):
        strip_flag = 0
        allow_tags = []
        position = context['position']
        terminator = context['details']['quote']
        vectors = {1:set()}
        suffix = '//\\'
        test_count = 0
        q = Queue()
        for function in functions:
            vector = terminator + script_context + jfillings + function + jfillings + suffix
            q.put(vector)
            init_vector = vector
            MAX_ITERATION = 3
            iteration_count = 0
            while not q.empty() and iteration_count < MAX_ITERATION:
                test_count += 1
                vector = q.get()
                iteration_count += 1
                if log_lock:
                    with log_lock:
                        if tester.bugoracle_pro(test_put_path, vector, position, init_vector):
                            return vector, test_count
                else:
                    if tester.bugoracle_pro(test_put_path, vector, position, init_vector):
                        return vector, test_count
                pre_function_calls = parse_xt_file(feedback_dir)
                feedback_message = parse_logs(feedback_dir, vector)
                if input_similarity(feedback_message, vector):

                    matched_substrings = get_matched_string(feedback_message)
                    function_similarity = 0
                    function_matched_substring = None
                    for matched_substring in matched_substrings: 
                        current_function_similarity = calculate_cosine_similarity(function, matched_substring)
                        if current_function_similarity > function_similarity:
                            function_similarity = current_function_similarity
                            function_matched_substring = matched_substring
                    new_vectors = set()
                    if function_similarity > 0.8:
                        new_vectors = function_mutate(vector,function_matched_substring)
                    else:
                        new_vectors = function_mutate(vector,function)

                    if new_vectors:
                        flag , vector, test_count = tester.bugoracle_select(test_put_path, new_vectors, position, init_vector, test_count, pre_function_calls)
                        if flag:
                            return vector, test_count
                        q.put(vector)
                if q.empty():
                    break
        if strip_flag == 0 or (strip_flag and "script" in allow_tags):
            for function in functions:
                vector = script_endtag + script_starttag + function + jfillings + suffix + script_endtag
                q.put(vector)
                init_vector = vector
                MAX_ITERATION = 3
                iteration_count = 0
                while not q.empty() and iteration_count < MAX_ITERATION:
                    test_count += 1
                    vector = q.get()
                    iteration_count += 1

                    if log_lock:
                        with log_lock:
                            if tester.bugoracle_pro(test_put_path, vector, position, init_vector):
                                return vector, test_count
                    else:
                        if tester.bugoracle_pro(test_put_path, vector, position, init_vector):
                            return vector, test_count
                    pre_function_calls = parse_xt_file(feedback_dir)
                    feedback_message = parse_logs(feedback_dir, vector)
                    if feedback_message['htmlencode.log']:
                        return None, test_count
                    if feedback_message['strip_tags.log']:
                        for item in feedback_message['strip_tags.log']:
                            if 'Allow Tags' in item:
                                if isinstance(item['Allow Tags'], str):
                                    allow_tags = extract_tags(item['Allow Tags'])
                                    strip_flag = 1
                            else:
                                return None, test_count
                    if input_similarity(feedback_message, vector):

                        matched_substrings = get_matched_string(feedback_message)
                        inline = script_starttag + script_endtag
                        inline_similarity = 0
                        function_similarity = 0
                        inline_matched_substring = set()
                        function_matched_substring = set()

                        for matched_substring in matched_substrings:
                            current_inline_similarity = calculate_cosine_similarity(inline, matched_substring)
                            if current_inline_similarity > 0.8:
                                inline_similarity = current_inline_similarity
                                inline_matched_substring.add(matched_substring)
                            
                            current_function_similarity = calculate_cosine_similarity(function, matched_substring)
                            if current_function_similarity > 0.8:
                                function_similarity = current_function_similarity
                                function_matched_substring.add(matched_substring)


                        new_vectors = set()
                        if inline_similarity > 0.8:
                            new_vectors.update(inline_mutate(vector, inline_matched_substring))
                        elif function_similarity > 0.8:
                            new_vectors.update(function_mutate(vector,function_matched_substring))
                        else:
                            break
                        if new_vectors:
                            flag , vector, test_count = tester.bugoracle_select(test_put_path, new_vectors, position, init_vector, test_count, pre_function_calls)
                            if flag:
                                return vector, test_count
                            q.put(vector)
                    if q.empty():
                        break

        for protocolsAttribute, tags in protocolsAttributes.items():
            for tag in tags:
                if strip_flag and tag not in allow_tags:
                    continue
                for protocol in protocols:
                    for function in functions:
                        for filling in fillings:
                            generated_tag = generate_tag(tag, {'id':'1',protocolsAttribute:protocol + ':' +function},{}, filling)
                            vector = script_endtag + generated_tag[1]
                            init_vector = vector

                            q.put(vector)
                            MAX_ITERATION = 3
                            iteration_count = 0
                            while not q.empty() and iteration_count < MAX_ITERATION:
                                test_count += 1
                                vector = q.get()
                                iteration_count += 1
                                if log_lock:
                                    with log_lock:
                                        if tester.bugoracle_pro(test_put_path, vector, position, init_vector):
                                            return vector, test_count
                                else:
                                    if tester.bugoracle_pro(test_put_path, vector, position, init_vector):
                                        return vector, test_count
                                function_calls = parse_xt_file(feedback_dir)
                                feedback_message = parse_logs(feedback_dir, vector)
                                if feedback_message['htmlencode.log']:
                                    return None, test_count
                                if feedback_message['strip_tags.log']:
                                    for item in feedback_message['strip_tags.log']:
                                        if 'Allow Tags' in item:
                                            if isinstance(item['Allow Tags'], str):
                                                allow_tags = extract_tags(item['Allow Tags'])
                                                strip_flag = 1
                                        else:
                                            return None, test_count
                                if input_similarity(feedback_message, vector):
                                    matched_substrings = get_matched_string(feedback_message)
                                    protocols_substring = generate_tag(tag, {'id':'1',protocolsAttribute:protocol},{},filling)[1]
                                    protocols_similarity = 0
                                    function_similarity = 0
                                    protocols_matched_substring = set()
                                    function_matched_substring = set()
                                    for matched_substring in matched_substrings:
                                        current_protocols_similarity = calculate_cosine_similarity(protocols_substring, matched_substring)
                                        if current_protocols_similarity > protocols_similarity:
                                            protocols_similarity = current_protocols_similarity
                                            protocols_matched_substring.add(matched_substring)
                                        
                                        current_function_similarity = calculate_cosine_similarity(function, matched_substring)
                                        if current_function_similarity > function_similarity:
                                            function_similarity = current_function_similarity
                                            function_matched_substring.add(matched_substring)
                                    if protocols_similarity > 0.8:
                                        new_vectors = protocols_mutate(vector, protocols_matched_substring)
                                    elif function_similarity > 0.8:
                                        new_vectors = function_mutate(vector,function_matched_substring)
                                    else:
                                        new_vectors = function_mutate(vector,function)
                                        new_vectors.update(protocols_mutate(vector, (tag,protocolsAttribute,protocol)))
                                    
                                    if new_vectors:
                                        flag , vector, test_count = tester.bugoracle_select(test_put_path, new_vectors, position, init_vector, test_count, pre_function_calls)
                                        if flag:
                                            return vector, test_count
                                        q.put(vector)
                                if q.empty():
                                    break
        for eventHandler, tags in eventHandlers.items():
            for tag in tags:
                if strip_flag and tag not in allow_tags:
                    continue
                for function in functions:
                    for filling in fillings:
                        generated_tag = generate_tag(tag,{'id':'1'},{eventHandler:function},filling)
                        vector = script_endtag + generated_tag[1]
                        init_vector = vector
                        q.put(vector)
                        MAX_ITERATION = 3
                        iteration_count = 0
                        while not q.empty() and iteration_count < MAX_ITERATION:
                            test_count += 1
                            vector = q.get()
                            iteration_count += 1
                            if log_lock:
                                with log_lock:
                                    if tester.bugoracle_pro(test_put_path, vector, position, init_vector):
                                        return vector, test_count
                            else:
                                if tester.bugoracle_pro(test_put_path, vector, position, init_vector):
                                    return vector, test_count
                            function_calls = parse_xt_file(feedback_dir)
                            feedback_message = parse_logs(feedback_dir, vector)
                            if feedback_message['htmlencode.log']:
                                return None, test_count
                            if feedback_message['strip_tags.log']:
                                for item in feedback_message['strip_tags.log']:
                                    if 'Allow Tags' in item:
                                        if isinstance(item['Allow Tags'], str):
                                            allow_tags = extract_tags(item['Allow Tags'])
                                            strip_flag = 1
                                    else:
                                        return None, test_count
                            if input_similarity(feedback_message, vector):
                                matched_substrings = get_matched_string(feedback_message)
                                events = generate_tag(tag,{'id':'1'},{eventHandler:''},filling)[1]
                                events_similarity = 0
                                function_similarity = 0
                                events_matched_substring = None
                                function_matched_substring = None
                                for matched_substring in matched_substrings:
                                    current_events_similarity = calculate_cosine_similarity(events, matched_substring)
                                    if current_events_similarity > events_similarity:
                                        events_similarity = current_events_similarity
                                        events_matched_substring = matched_substring
                                    
                                    current_function_similarity = calculate_cosine_similarity(function, matched_substring)
                                    if current_function_similarity > function_similarity:
                                        function_similarity = current_function_similarity
                                        function_matched_substring = matched_substring
                                if events_similarity > 0.8:
                                    new_vectors = events_mutate(vector,events_matched_substring)
                                if function_similarity > 0.8:
                                    new_vectors = function_mutate(vector,function_matched_substring)
                                else:
                                    break
                                
                                if new_vectors:
                                    flag , vector, test_count = tester.bugoracle_select(test_put_path, new_vectors, position, init_vector, test_count, pre_function_calls)
                                    if flag:
                                        return vector, test_count
                                    q.put(vector)
                            if q.empty():
                                break

        return  None , test_count
    