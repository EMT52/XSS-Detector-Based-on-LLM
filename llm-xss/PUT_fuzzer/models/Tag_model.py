from mimetypes import init
from textwrap import fill
from threading import Lock
from sklearn.covariance import log_likelihood
from .config_model import payloads, functions, script_starttag, script_endtag, jfillings, protocols, protocolsAttributes, eventHandlers, feedback_log, xt_file, fillings, suffix, lessfilling, greaterfilling, feedback_dir
from .helper_model import generate_tag, read_matched_substring, calculate_cosine_similarity, str_replace_params, parse_logs, extract_tags, chose_most_similar, input_similarity, get_matched_string, parse_xt_file
import random
from .evasion_model import function_mutate, inline_mutate, protocols_mutate, events_mutate
import threading
from queue import Queue

log_lock = Lock()

class TagsCharacters:
    def __init__(self):
        self.javascripttrigger = [
            ("<script>","</script>"),
            ("<a href=javascript:",">click_me</a>"),
            ("<a href=\"javascript:","\">click_me</a>"),
            ("<a href='javascript:","'>click_me</a>"),
            ("<iframe src=javascript:",">")
        ]
    
    def html_attackgrammar(self, tester, context, test_put_path):
        position = context['position']
        strip_flag = 0
        allow_tags = []
        test_count = 0
        q = Queue()
        if strip_flag == 0 or (strip_flag and "script" in allow_tags):
            for function in functions:
                vector = script_starttag + function + jfillings + suffix + script_endtag
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
                            vector = generated_tag[1]
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
                        vector = generated_tag[1]
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

        return None, test_count