import re
from bs4 import BeautifulSoup
from .config_model import unique_probe

def extractScripts(response):
    scripts = []
    matches = re.findall(r'(?s)<script.*?>(.*?)</script>', response.lower())
    for match in matches:
        if unique_probe.lower() in match:
            scripts.append(match)
    return scripts

def escaped(position, string):
    usable = string[:position][::-1]
    match = re.search(r'^\\*', usable)
    if match:
        match = match.group()
        if len(match) == 1:
            return True
        elif len(match) % 2 == 0:
            return False
        else:
            return True
    else:
        return False
    
def isBadContext(position, non_executable_contexts):
    badContext = ''
    for each in non_executable_contexts:
        if each[0] < position < each[1]:
            badContext = each[2]
            break
    return badContext

def context_parser(response):
    database = {}

    reflections = response.count(unique_probe)
    position_and_context = {}
    environment_details = {}
    script_checkable = response
    for script in extractScripts(script_checkable):
        script_start = script_checkable.lower().find(script.lower())
        if script_start == -1:
            continue
        occurences = re.finditer(r'(%s.*?$)' % re.escape(unique_probe), script, re.MULTILINE)
        if occurences:
            for occurence in occurences:
                thisPosition = script_start + occurence.start(1)
                position_and_context[thisPosition] = 'script'
                environment_details[thisPosition] = {}
                environment_details[thisPosition]['details'] = {'quote' : ''}
                for i in range(len(occurence.group())):
                    currentChar = occurence.group()[i]
                    if currentChar in ('/', '\'', '`', '"') and not escaped(i, occurence.group()):
                        environment_details[thisPosition]['details']['quote'] = currentChar
                    elif currentChar in (')', ']', '}', '}') and not escaped(i, occurence.group()):
                        break
                script_checkable = script_checkable.replace(unique_probe, '', 1)
    try:
        soup = BeautifulSoup(response, 'html.parser')
        if len(position_and_context) < reflections:
            for tag in soup.find_all(True):
                for attr, attr_value in tag.attrs.items():
                    try:
                        target_str = unique_probe
                        match = re.search(target_str, attr_value)
                        
                        if match:
                            start_pos = match.start()
                            end_pos = match.end() 
                            
                            attr_start_index = response.find(f'{attr}=', response.find(f'<{tag.name}'))
                    
                            quote_pos_double = response.find('"', attr_start_index + len(f'{attr}='))
                            quote_pos_single = response.find("'", attr_start_index + len(f'{attr}='))

                            if quote_pos_double == -1 and quote_pos_single == -1:
                                start_index = attr_start_index + len(f'{attr}=')
                            elif quote_pos_double == -1:
                                start_index = quote_pos_single
                            elif quote_pos_single == -1:
                                start_index = quote_pos_double
                            else:
                                start_index = min(quote_pos_double, quote_pos_single, key=lambda x: abs(x - (attr_start_index + len(f'{attr}='))))
                            if attr in ['href', 'src']:
                                position_and_context[start_index + start_pos] = 'protocols'
                            else:
                                position_and_context[start_index + start_pos] = 'attribute'
                            
                            if response[start_index] == '"':
                                quote_type = '"'
                            elif response[start_index] == "'":
                                quote_type = "'"
                            else:
                                quote_type = "\"" 
                            environment_details[start_index + start_pos] = {
                                'details': {
                                    'tag': tag,
                                    'type': "value",
                                    'quote': quote_type,
                                    'value': attr_value,
                                    'name': attr
                                }
                            }
                    except:
                        pass
    except:
        attribute_context = re.finditer(r'<[^>]*?(%s)[^>]*?>' % re.escape(unique_probe), response)

        for occurrence in attribute_context:
            match = occurrence.group(0) 
            tag_start_pos = occurrence.start() 
            parts = re.split(r'\s+', match) 
            tag = parts[0][1:]

            for part in parts[1:]:
                if unique_probe in part:
                    Type, quote, name, value = '', '', '', ''
                    attr_positions = [m.start() for m in re.finditer(unique_probe, part)]

                    for attr_pos in attr_positions:
                        if '=' in part:
                            quote_match = re.search(r'=([\'`"])?', part)
                            if quote_match:
                                quote = quote_match.group(1)

                            name_and_value = part.split('=')[0], '='.join(part.split('=')[1:])
                            if unique_probe == name_and_value[0]:
                                Type = 'name'
                            else:
                                Type = 'value'

                            name = name_and_value[0]
                            value = name_and_value[1].rstrip('>').rstrip(quote).lstrip(quote)
                        else:
                            Type = 'flag'

                        attribute_match = re.search(r'(\w+)\s*=', part)
                        if attribute_match:
                            attribute_name = attribute_match.group(1)
                            if attribute_name in ['href', 'src']:
                                position_and_context[tag_start_pos + attr_pos] = 'protocols'
                            else:
                                position_and_context[tag_start_pos + attr_pos] = 'attribute'

                        environment_details[tag_start_pos + attr_pos] = {
                            'details': {
                                'tag': tag,
                                'type': Type,
                                'quote': quote,
                                'value': value,
                                'name': name
                            }
                        }
    if len(position_and_context) < reflections:
        html_context = re.finditer(unique_probe, response)
        for occurence in html_context:
            thisPosition = occurence.start()
            if thisPosition not in position_and_context:
                position_and_context[occurence.start()] = 'html'
                environment_details[thisPosition] = {}
                environment_details[thisPosition]['details'] = {}
    database = {}
    for i in sorted(position_and_context):
        database[i] = {}
        database[i]['position'] = i
        database[i]['context'] = position_and_context[i]
        database[i]['details'] = environment_details[i]['details']

    bad_contexts = re.finditer(r'(?s)(?i)<(style|template|textarea|title|noembed|noscript)>[.\s\S]*(%s)[.\s\S]*</\1>' % unique_probe, response)
    non_executable_contexts = []
    for each in bad_contexts:
        non_executable_contexts.append([each.start(), each.end(), each.group(1)])

    if non_executable_contexts:
        for key in database.keys():
            position = database[key]['position']
            badTag = isBadContext(position, non_executable_contexts)
            if badTag:
                database[key]['details']['badTag'] = badTag
            else:
                database[key]['details']['badTag'] = ''
    return database
