import os
import subprocess
import json
import re
import requests
from numpy import true_divide
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.alert import Alert
from selenium.common.exceptions import WebDriverException, NoSuchElementException, JavascriptException

from .helper_model import edit_distance, find_most_similar, clear_log_files, caculate_similarity, parse_xt_file, compare_function_calls, extract_temp_params, extract_main_param
from .config_model import feedback_dir, fuzz_cases, protocolsAttributes, xt_file
from bs4 import BeautifulSoup,MarkupResemblesLocatorWarning, XMLParsedAsHTMLWarning
from esprima import parseScript
import time
import warnings
NONE = 0
LOW = 1
MEDIUM = 2
HIGH = 3
def js_ast_traversal(node):
    conf = NONE

    if isinstance(node, list):
        for stmt in node:
            res = js_ast_traversal(stmt)
            if res == HIGH:
                return HIGH
            conf = max(res, conf)

    elif 'esprima.nodes.CallExpression' in str(type(node)):
        if node.callee.name in ["alert", "prompt", "confirm"]:
            res = js_ast_traversal(node.arguments)
            if not res: 
                return HIGH
            if res > NONE:
                return HIGH
            conf = max(res, conf)

    elif 'esprima.nodes.TaggedTemplateExpression' in str(type(node)):
        if node.quasi.type == 'TemplateLiteral' and node.tag.name in ["alert", "prompt", "confirm"]:
            res = js_ast_traversal(node.quasi.quasis)
            if res > NONE:
                return HIGH
            conf = max(res, conf)

    if "esprima.nodes" in str(type(node)):
        for attr in dir(node):
            res = js_ast_traversal(getattr(node, attr))
            if res == HIGH:
                return HIGH
            conf = max(res, conf)

    if isinstance(node, str):
        pass

    return conf


def handle_script(raw_code):
    try:
        script = parseScript(raw_code)
        return js_ast_traversal(script.body)
    except Exception as e:
        return NONE
def trigger_event(driver, action_tag, event_type, script):
    try:
        driver.execute_script(script, action_tag)
        try:
            alert = driver.switch_to.alert
            alert_text = alert.text
            if str(711) in alert_text:
                alert.accept()
                return True
            else:
                alert.accept()
        except:
            pass
    except JavascriptException as e:
        pass
    return False

class Sanitizer_Tester:
    def __init__(self):
        self.pattern = r"expects parameter \d+ to be array"
        self.error_files = []
        self.error_details = []
    
    def test_context(self, test_put_path, payload):
        # 修复: 正确提取 URI (test-app/1/index.php)
        uri = f"{test_put_path.split('/')[-3]}/{test_put_path.split('/')[-2]}/{test_put_path.split('/')[-1]}"
        url = f"http://localhost/{uri}"
        
        # 动态提取主要参数名
        main_param = extract_main_param(test_put_path)
        test_url = f"{url}?{main_param}={payload}"
        
        chromedriver_path = "/usr/local/bin/chromedriver/chromedriver"

        if not os.path.isfile(chromedriver_path):
            raise FileNotFoundError(f"chromedriver not found at: {chromedriver_path}")

        options = Options()
        options.binary_location = "/opt/chrome/chrome"
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")

        driver = webdriver.Chrome(executable_path=chromedriver_path, chrome_options=options)
        try:
            driver.get(test_url)
            time.sleep(2)

            response_text = driver.execute_script("return document.documentElement.outerHTML;")

            return response_text

        finally:
            driver.quit()

    def bugoracle_pro(self, test_put_path, payload, position, init_vector):
        for fuzz_case in fuzz_cases:
            clear_log_files(feedback_dir)
            response = self.test_filter(test_put_path, payload, json.dumps(fuzz_case))
            if self.htmlparser_verify(response, test_put_path):
                if self.bugoracle(test_put_path, payload, json.dumps(fuzz_case)):
                    return True
            elif payload in response:
                # 降级验证：htmlparser_verify 失败但 payload 确实被反射到响应中
                # BS4 解析和真实浏览器可能有差异，给予有限的直接验证机会
                if self.bugoracle(test_put_path, payload, json.dumps(fuzz_case)):
                    return True
        return False
    
    def htmlparser_verify(self,response, test_put_path):
        try:
            warnings.filterwarnings("always", category=MarkupResemblesLocatorWarning)
            warnings.filterwarnings("always", category=XMLParsedAsHTMLWarning)
            with warnings.catch_warnings(record=True) as warning_list:
                soup = BeautifulSoup(response, "html.parser")
                for warning in warning_list:
                    if warning.category in (MarkupResemblesLocatorWarning, XMLParsedAsHTMLWarning):
                        return  False
                for script in soup.find_all('script'):
                    confidence = handle_script(script.text)
                    if confidence == HIGH:
                        return True 

                for tag in soup.find_all():
                    for attr, value in tag.attrs.items():
                        if attr.lower().startswith("on"):
                            confidence = handle_script(value)
                            if confidence == HIGH:
                                return True
                        if attr.lower() in protocolsAttributes and value[:11].lower() == "javascript:":
                            protocol_value = value[11:]
                            confidence = handle_script(protocol_value)
                            if confidence == HIGH:
                                return True

                return False
        except Exception as e:
            return False
        return False


    def bugoracle_select(self, test_put_path, payloads, position, init_vector, test_count, pre_function_calls):
        max_similarity = -1
        most_similar_element = None
        for payload in payloads:
            test_count += 1
            for fuzz_case in fuzz_cases:
                clear_log_files(feedback_dir)
                response = self.test_filter(test_put_path, payload, json.dumps(fuzz_case))
                post_function_calls = parse_xt_file(feedback_dir)
                comparison_result = compare_function_calls(pre_function_calls, post_function_calls)
                if comparison_result:
                    most_similar_element = payload
                if self.htmlparser_verify(response, test_put_path) or comparison_result:
                    if self.bugoracle(test_put_path, payload, json.dumps(fuzz_case)):
                        return True, payload, test_count
        return False, most_similar_element, test_count

    def bugoracle(self, test_put_path, payload, other):
        # 修复: 正确提取 URI (test-app/1/index.php)
        uri = f"{test_put_path.split('/')[-3]}/{test_put_path.split('/')[-2]}/{test_put_path.split('/')[-1]}"
        url = f"http://localhost/{uri}"
        
        # 动态提取主要参数名
        main_param = extract_main_param(test_put_path)
        test_url = f"{url}?{main_param}={payload}"
        
        with open(test_put_path) as f:
            temp_params = extract_temp_params(f.read())
        with open(test_put_path.replace("index.php", "function_definition.php")) as f:
            temp_params.extend(extract_temp_params(f.read()))
        for temp_param in temp_params:
            test_url += f"&{temp_param}={other}"
        chromedriver_path = "/usr/local/bin/chromedriver/chromedriver"
        if not os.path.isfile(chromedriver_path):
            raise FileNotFoundError(f"chromedriver not found at: {chromedriver_path}")

        options = Options()
        options.binary_location = "/opt/chrome/chrome"
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--blink-settings=imagesEnabled=false")
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--incognito")
        driver = webdriver.Chrome(executable_path=chromedriver_path, chrome_options=options)
        driver.delete_all_cookies()
        try:
            try:
                driver.get(test_url)
            except WebDriverException as e:
                driver.quit()
            try:
                alert = driver.switch_to.alert
                alert_text = alert.text
                if str(711) in alert_text:
                    alert.accept() 
                    return True
                else:
                    alert.accept()
            except:
                pass
            response_html = driver.page_source
            soup = BeautifulSoup(response_html, "html.parser")
            event_tags = []
            for tag in soup.find_all():
                event_attrs = {attr: value for attr, value in tag.attrs.items() if attr.lower().startswith("on")}
                if event_attrs:
                    event_tags.append((tag, event_attrs))

            for tag, event_attrs in event_tags:
                try:
                    element = None
                    if 'id' in tag.attrs:
                        element = driver.find_element(By.ID, tag['id'])
                    elif 'class' in tag.attrs:
                        element = driver.find_element(By.CLASS_NAME, tag['class'][0])
                    elif 'name' in tag.attrs:
                        element = driver.find_element(By.NAME, tag['name'])
                    else:
                        element = driver.find_element(By.XPATH, f"//{tag.name}")

                    if element:
                        for event_attr in event_attrs:
                            try:
                                script = f"arguments[0].{event_attr}();"
                                driver.execute_script(script, element)
                            except JavascriptException as e:
                                pass
                        try:
                            alert = driver.switch_to.alert
                            alert_text = alert.text
                            if '711' in alert_text:
                                alert.accept()
                                return True
                            else:
                                alert.accept()
                        except:
                            pass

                except NoSuchElementException:
                    pass
                except Exception as e:
                    pass

            for href_tag in protocolsAttributes['href']:
                try:
                    links = driver.find_elements(By.TAG_NAME, href_tag)

                    for link in links:
                        try:
                            link.click()

                            try:
                                alert = driver.switch_to.alert
                                alert_text = alert.text
                                if str(711) in alert_text:
                                    alert.accept()
                                    return True
                                else:
                                    alert.accept()
                            except:
                                pass

                            driver.back()
                        except:
                            pass
                except:
                    pass
            try:
                input_element = driver.find_element(By.ID, "1")
                input_element.send_keys("xssky")
                try:
                    alert = driver.switch_to.alert 
                    alert_text = alert.text  
                    if str(711) in alert_text:
                        alert.accept() 
                        return True
                    else:
                        alert.accept()
                except:
                    pass
            except:
                pass

            try:
                action_tag = driver.find_element(By.ID, "1")
                driver.execute_script("arguments[0].click();", action_tag)
                try:
                    alert = driver.switch_to.alert
                    alert_text = alert.text
                    if str(711) in alert_text:
                        alert.accept()
                        return True
                    else:
                        alert.accept()
                except:
                    pass
                driver.execute_script("arguments[0].dispatchEvent(new Event('mouseover', { bubbles: true }));", action_tag)
                try:
                    alert = driver.switch_to.alert
                    alert_text = alert.text
                    if str(711) in alert_text:
                        alert.accept()
                        return True
                    else:
                        alert.accept()
                except:
                    pass
                driver.execute_script("""
                    const event = new PointerEvent('pointerenter', {
                        bubbles: true,
                        cancelable: true,
                        composed: true,
                        pointerType: 'mouse',
                        isPrimary: true
                    });
                    arguments[0].dispatchEvent(event);
                """, action_tag)
                try:
                    alert = driver.switch_to.alert
                    alert_text = alert.text
                    if str(711) in alert_text:
                        alert.accept()
                        return True
                    else:
                        alert.accept()
                except:
                    pass
                driver.execute_script("""
                    arguments[0].open = !arguments[0].open;
                    const event = new Event('toggle', {
                        bubbles: true,
                        cancelable: true
                    });
                    arguments[0].dispatchEvent(event);
                """, action_tag)
                try:
                    alert = driver.switch_to.alert
                    alert_text = alert.text
                    if str(711) in alert_text:
                        alert.accept()
                        return True
                    else:
                        alert.accept()
                except:
                    pass
            except:
                pass
            try:
                try:
                    action_tag = driver.find_element(By.NAME, "snow1nd")
                except NoSuchElementException:
                    try:
                        action_tag = driver.find_element(By.ID, "1")
                    except NoSuchElementException:
                        action_tag = driver.find_element(By.XPATH, "//*[contains(text(), 'snow1nd')]")
                events = {
                    "onclick": "arguments[0].click();",
                    "onmouseover": "arguments[0].dispatchEvent(new Event('mouseover', { bubbles: true }));",
                    "onpointerover": """
                        const event = new PointerEvent('pointerenter', {
                            bubbles: true,
                            cancelable: true,
                            composed: true,
                            pointerType: 'mouse',
                            isPrimary: true
                        });
                        arguments[0].dispatchEvent(event);
                    """,
                    "ontoggle": """
                        arguments[0].open = !arguments[0].open;
                        const event = new Event('toggle', { bubbles: true, cancelable: true });
                        arguments[0].dispatchEvent(event);
                    """
                }

                for event_type, script in events.items():
                    if trigger_event(driver, action_tag, event_type, script):
                        return True
                
            except:
                pass

            return False
        finally:
            driver.quit()

    def test_filter(self, test_put_path, payload, other, max_output_size=10 * 1024 * 1024): 
        # 修复: 正确提取 URI (test-app/1/index.php)
        uri = f"{test_put_path.split('/')[-3]}/{test_put_path.split('/')[-2]}/{test_put_path.split('/')[-1]}"
        url = f"http://localhost/{uri}"
        
        # 动态提取主要参数名
        main_param = extract_main_param(test_put_path)
        params = {
            main_param: payload
        }
        
        with open(test_put_path) as f:
            temp_params = extract_temp_params(f.read())
        with open(test_put_path.replace("index.php", "function_definition.php")) as f:
            temp_params.extend(extract_temp_params(f.read()))
        for temp_param in temp_params:
            params[temp_param] = other

        try:
            response = requests.get(url, params=params, timeout=10)
            if response.status_code != 200:
                if test_put_path not in self.error_files:
                    self.error_files.append(test_put_path)
                    self.error_details.append(f"{test_put_path}\nHTTP Error: {response.status_code}")
                return ""

            stdout = response.content

            if len(stdout) > max_output_size:
                stdout = stdout[:max_output_size] + b'... [truncated]'

            return stdout.decode('utf-8').strip()

        except requests.exceptions.RequestException as e:
            if test_put_path not in self.error_files:
                self.error_files.append(test_put_path)
                self.error_details.append(f"{test_put_path}\nRequest Error: {str(e)}")
            return ""
            
    def get_error_files(self):
        return self.error_files
    
    def save_error_details(self, error_file):
        error_details_str = "\n".join(self.error_details)

        with open(error_file, 'a', encoding='utf-8') as f:
            f.write(f"[+]共{len(self.error_files)}个php文件报错\n{self.error_files}\n\n")
            f.write(error_details_str)
        print("[+] error信息保存成功！")
        return 