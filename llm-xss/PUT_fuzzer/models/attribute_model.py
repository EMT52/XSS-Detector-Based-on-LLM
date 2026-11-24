from .config_model import payloads, functions, eventHandlers, terminators, protocolsAttributes,xt_file, protocols, protocols_attributes, greaterfilling, jfillings, fillings, lessfilling, feedback_log, script_starttag, script_endtag, feedback_dir
from .helper_model import read_matched_substring, calculate_cosine_similarity, parse_xt_file, generate_tag, str_replace_params, parse_logs, extract_tags, htmlencode_mode, chose_most_similar, input_similarity, get_matched_string
from .evasion_model import events_mutate, function_mutate, inline_mutate
import random
from threading import Lock
import threading
from queue import Queue
log_lock = Lock()
def attribute_attackgrammar(tester, context, test_put_path):
    Type = context['details']['type']
    real_terminator = context['details']['quote']
    tag = context['details']['tag']
    name = context['details']['name']
    value = context['details']['value']
    position = context['position']

    allow_tags = []
    strip_flag = 0
    test_count = 0
    q = Queue()
    break_flag = 0
    if Type == 'value':
        for function in functions:
            for event, tags in eventHandlers.items():
                if tag in tags or 'html' in tags:
                    for filling in fillings:
                        for terminator in terminators:
                            vector = terminator + filling + 'id=1' + filling +'name=snow1nd' + filling +  event + '=' + function + '//' + terminator
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
                                if real_terminator and htmlencode_mode(real_terminator, feedback_message)  == False:
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
                                            event_matched_substring = matched_substring
                                            event_similarity = current_event_similarity
                                        current_function_similarity = calculate_cosine_similarity(function, matched_substring)
                                        if current_function_similarity > function_similarity:
                                            function_matched_substring = matched_substring
                                            function_similarity = current_function_similarity
                                    new_vectors = set()
                                    if event_similarity > 0.8:
                                        new_vectors.update(events_mutate(vector, event_matched_substring))
                                    elif function_similarity > 0.8:
                                        new_vectors.update(function_mutate(vector, function_matched_substring))
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
                    for event_tag in tags:
                        if strip_flag and event_tag not in allow_tags:
                            continue
                        for filling in fillings:
                            for terminator in terminators:
                                generated_tag = generate_tag(event_tag,{'id':'1'},{event:function}, filling)
                                vector = terminator + greaterfilling + generated_tag[1] + lessfilling + terminator
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
                                    pre_function_calls = parse_xt_file(feedback_dir)
                                    feedback_message = parse_logs(feedback_dir, vector)
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
                                        event_similarity = 0
                                        function_similarity = 0
                                        event_matched_substring = None
                                        function_matched_substring = None
                                        for matched_substring in matched_substrings:
                                            current_event_similarity = calculate_cosine_similarity(event, matched_substring)
                                            if current_event_similarity > event_similarity:
                                                event_matched_substring = matched_substring
                                                event_similarity = current_event_similarity
                                            current_function_similarity = calculate_cosine_similarity(function, matched_substring)
                                            if current_function_similarity > function_similarity:
                                                function_matched_substring = matched_substring
                                                function_similarity = current_function_similarity
                                        new_vectors = set()
                                        if event_similarity > 0.8:
                                            new_vectors.update(events_mutate(vector, event_matched_substring))
                                        elif function_similarity > 0.8:
                                            new_vectors.update(function_mutate(vector, function_matched_substring))
                                        else:
                                            break

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
        break_flag = 0
        for protocolsAttribute, tags in protocolsAttributes.items():
            for protocol_tag in tags:
                if strip_flag and protocol_tag not in allow_tags:
                    continue
                for protocol in protocols:
                    for function in functions:
                        if tag == protocol_tag:
                            for filling in fillings:
                                for terminator in terminators:
                                    vector = terminator + filling + 'id=1' + filling + 'name=snow1nd' + filling + protocolsAttribute + '=' + protocol + ':' + function + '//' +terminator
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
                                        pre_function_calls = parse_xt_file(feedback_dir)
                                        feedback_message = parse_logs(feedback_dir, vector)
                                        if real_terminator and htmlencode_mode(real_terminator, feedback_message) == False:
                                            return None , test_count
                                        if input_similarity(feedback_message, vector):
                                            matched_substrings = get_matched_string(feedback_message)
                                            protocol_similarity = 0
                                            function_similarity = 0
                                            protocol_matched_substring = None
                                            function_matched_substring = None
                                            for matched_substring in matched_substrings:
                                                current_protocol_similarity = calculate_cosine_similarity(protocolsAttribute, matched_substring)
                                                if current_protocol_similarity > protocol_similarity:
                                                    protocol_matched_substring = matched_substring
                                                    protocol_similarity = current_protocol_similarity
                                                current_function_similarity = calculate_cosine_similarity(function, matched_substring)
                                                if current_function_similarity > function_similarity:
                                                    function_matched_substring = matched_substring
                                                    function_similarity = current_function_similarity
                                            new_vectors = set()
                                            if protocol_similarity > 0.8:
                                                new_vectors = events_mutate(vector, protocol_matched_substring)
                                            elif function_similarity > 0.8:
                                                new_vectors = function_mutate(vector, function_matched_substring)
                                            else:
                                                new_vectors = function_mutate(vector, function)
                                                new_vectors.update(events_mutate(vector, protocolsAttribute))

                                            if new_vectors:
                                                flag , vector, test_count = tester.bugoracle_select(test_put_path, new_vectors, position, init_vector, test_count, pre_function_calls)
                                                if flag:
                                                    return vector, test_count
                                                q.put(vector)
                                        if q.empty():
                                            break
                        else:
                            for filling in fillings:
                                for terminator in terminators:
                                    generated_tag = generate_tag(protocol_tag, {"id":"1",protocolsAttribute:protocol + ':' + function },{}, filling)
                                    vector = terminator + greaterfilling + generated_tag[1] + lessfilling + terminator
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
                                        pre_function_calls = parse_xt_file(feedback_dir)
                                        feedback_message = parse_logs(feedback_dir, vector)
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
                                            protocol_similarity = 0
                                            function_similarity = 0
                                            protocol_matched_substring = None
                                            function_matched_substring = None
                                            for matched_substring in matched_substrings:
                                                current_protocol_similarity = calculate_cosine_similarity(protocolsAttribute, matched_substring)
                                                if current_protocol_similarity > protocol_similarity:
                                                    protocol_matched_substring = matched_substring
                                                    protocol_similarity = current_protocol_similarity
                                                current_function_similarity = calculate_cosine_similarity(function, matched_substring)
                                                if current_function_similarity > function_similarity:
                                                    function_matched_substring = matched_substring
                                                    function_similarity = current_function_similarity
                                            new_vectors = set()
                                            if protocol_similarity > 0.8:
                                                new_vectors = events_mutate(vector, protocol_matched_substring)
                                            elif function_similarity > 0.8:
                                                new_vectors = function_mutate(vector, function_matched_substring)
                                            else:
                                                new_vectors = function_mutate(vector, function)
                                                new_vectors.update(events_mutate(vector, protocolsAttribute))

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

        break_flag = 0
        for function in functions:
            for terminator in terminators:
                vector = terminator + greaterfilling + script_starttag + function + jfillings + script_endtag + lessfilling +terminator
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
                    pre_function_calls = parse_xt_file(feedback_dir)
                    feedback_message = parse_logs(feedback_dir, vector)
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
                        else:
                            break


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
    return None , test_count