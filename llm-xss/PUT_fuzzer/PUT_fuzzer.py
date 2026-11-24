import os
import time
from tqdm import tqdm
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
import threading

from models.verify_model import Sanitizer_Tester
from models.output_model import save_output, record_llm_result
from models.context_model import context, TimeoutException
import logging
import traceback

# 创建logger实例
logger = logging.getLogger(__name__)

def parse_args():
    parser = argparse.ArgumentParser(description="PUT fuzzer with LLM enhancement")
    parser.add_argument('--test_path', type=str,
                        default=os.environ.get('XSS_WEB_ROOT', '/var/www/html/'),
                        help='PUT web directory; defaults to XSS_WEB_ROOT or /var/www/html/')
    parser.add_argument('--output', default='output/results.json',
                       help='Current-run JSON output path; previous contents are archived')
    parser.add_argument('--enable_llm', action='store_true',
                       help='Enable LLM-enhanced testing')
    parser.add_argument('--llm_provider', type=str, default='qwen',
                       choices=['qwen', 'ernie', 'zhipu', 'deepseek', 'openai', 'claude', 'local'],
                       help='LLM provider to use')
    parser.add_argument('--llm_api_key', type=str,
                       help='API key for LLM service (or set via environment variable)')
    parser.add_argument('--llm_model', type=str,
                       help='LLM model name (optional, uses default if not specified)')
    parser.add_argument('--llm_api_base', type=str,
                       help='LLM API base URL (optional, overrides provider default endpoint, e.g. http://localhost:11434 for Ollama)')
    parser.add_argument('--timeout', type=int, default=120,
                       help='Timeout in seconds for each file test (default: 120)')
    parser.add_argument('--llm_workers', type=int, default=4,
                       help='Number of parallel workers for LLM testing (default: 4)')
    return parser.parse_args()

def process_file(test_put_path, context, results, results_lock, timeout=120):
    """
    处理单个文件的测试，带超时保护
    
    Args:
        test_put_path: 测试文件路径
        context: 上下文对象
        results: 结果字典（共享）
        results_lock: 线程锁
        timeout: 超时时间（秒）
    """
    # 创建本地results字典
    local_results = {
        "vulnerable_files": {},
        "safe_files": {},
        "cant_parse_files": []
    }
    
    try:
        local_results = context.test_put(test_put_path, local_results, timeout=timeout)
        
        # 使用锁保护共享的results字典
        with results_lock:
            results["vulnerable_files"].update(local_results.get("vulnerable_files", {}))
            results["safe_files"].update(local_results.get("safe_files", {}))
            results["cant_parse_files"].extend(local_results.get("cant_parse_files", []))
            
    except (TimeoutError, TimeoutException) as e:
        # 捕获两种超时异常
        logging.warning(f"[TIMEOUT] Test for {test_put_path} exceeded {timeout}s, skipping...")
        with results_lock:
            results["safe_files"][test_put_path] = {
                "test_count": 0,
                "error": f"timeout_{timeout}s"
            }
    except Exception as e:
        logging.error(f"[ERROR] Test for {test_put_path} failed: {e}")
        print(traceback.print_exc())
        with results_lock:
            results["safe_files"][test_put_path] = {
                "test_count": 0,
                "error": str(e)
            }

if __name__ =="__main__":
    args = parse_args()

    results = {
        "vulnerable_files": {},
        "safe_files": {},
        "cant_parse_files": [],
        "testing_duration": 0
    }
    
    # 添加线程锁保护共享的results字典
    results_lock = threading.Lock()
    
    test_path = args.test_path
    result_file = args.output

    start_time = time.time()

    tester = Sanitizer_Tester()

    context = context(
        tester,
        enable_llm=args.enable_llm,
        llm_provider=args.llm_provider,
        llm_api_key=args.llm_api_key,
        llm_model=args.llm_model,
        llm_api_base=args.llm_api_base
    )
    
    if args.enable_llm:
        print(f"[+] LLM Enhanced Mode: Enabled")
        print(f"[+] LLM Provider: {args.llm_provider}")
        print(f"[+] LLM Model: {args.llm_model or 'default'}")
        print(f"[+] LLM API Base: {args.llm_api_base or 'default'}")
        print(f"[+] LLM Workers: {args.llm_workers}")
    else:
        print(f"[+] LLM Enhanced Mode: Disabled")
    
    print(f"[+] Timeout per file: {args.timeout}s")
    
    cms_list = [item for item in os.scandir(test_path) if item.is_dir()]
    try:
        with ThreadPoolExecutor(max_workers=8) as executor:
            tasks = []
            
            # 先统计文件数量以准确显示进度
            file_list = []
            for cms_entry in os.scandir(test_path):
                if not cms_entry.is_dir():
                    continue
                for path_entry in os.scandir(cms_entry.path):
                    if not path_entry.is_dir():
                        continue
                    test_put_path = os.path.join(path_entry.path, "index.php")
                    if os.path.isfile(test_put_path):
                        file_list.append(test_put_path)
            
            print(f"[+] Found {len(file_list)} files to test")
            
            # 提交所有测试任务
            for test_put_path in file_list:
                future = executor.submit(
                    process_file,
                    test_put_path,
                    context,
                    results,
                    results_lock,
                    args.timeout
                )
                tasks.append(future)
            
            # 等待所有任务完成
            thread_times = []
            for future in tqdm(as_completed(tasks), total=len(tasks), desc="Processing files"):
                try:
                    thread_start_time = time.time()
                    future.result(timeout=args.timeout+10)
                    thread_end_time = time.time()
                    thread_times.append(thread_end_time - thread_start_time)
                except TimeoutError:
                    logging.warning(f"[TIMEOUT] A file test exceeded the timeout limit")
                    thread_times.append(args.timeout)
                except Exception as e:
                    logging.error(f"[ERROR] Task failed: {e}")
                    traceback.print_exc()
    finally:
        end_time = time.time()
        total_runtime = end_time - start_time
        total_thread_time = sum(thread_times)
        
        # 阶段2: LLM批量测试所有safe文件（如果启用LLM）
        if args.enable_llm and results["safe_files"]:
            print(f"\n[+] Starting LLM-enhanced testing for {len(results['safe_files'])} safe files...")
            print(f"[+] LLM parallel workers: {args.llm_workers}")
            logging.info(f"[LLM] Starting batch LLM testing for {len(results['safe_files'])} files with {args.llm_workers} workers")
            
            llm_start_time = time.time()
            llm_tested = 0
            llm_found = 0
            
            # 对所有safe文件进行LLM并行测试
            safe_files_list = list(results["safe_files"].keys())
            
            def process_llm_file(test_put_path):
                """单个文件的LLM测试任务"""
                try:
                    llm_result = context._try_llm_after_timeout(test_put_path, timeout=60)
                    return test_put_path, llm_result, None
                except Exception as e:
                    return test_put_path, None, e
            
            with ThreadPoolExecutor(max_workers=args.llm_workers) as llm_executor:
                llm_futures = [
                    llm_executor.submit(process_llm_file, path)
                    for path in safe_files_list
                ]
                
                for future in tqdm(as_completed(llm_futures), total=len(llm_futures), desc="LLM testing safe files"):
                    try:
                        test_put_path, llm_result, error = future.result(timeout=120)
                        
                        if error:
                            logger.error(f"[LLM] Error testing {test_put_path}: {error}")
                        with results_lock:
                            found = record_llm_result(
                                results, test_put_path, llm_result,
                                args.llm_provider, error=error,
                            )
                        if llm_result and llm_result.get("custom_payloads_tested", 0) > 0:
                            llm_tested += 1

                        if found:
                            llm_found += 1
                            logger.info(f"[LLM] ✅ Vulnerability found in {test_put_path}")
                        else:
                            logger.debug(f"[LLM] Status for {test_put_path}: "
                                         f"{results['safe_files'][test_put_path]['llm_details']['status']}")
                    
                    except TimeoutError:
                        logging.warning(f"[LLM] A file LLM test exceeded timeout")
                    except Exception as e:
                        logger.error(f"[LLM] Task failed: {e}")
            
            llm_end_time = time.time()
            llm_duration = llm_end_time - llm_start_time
            
            print(f"\n[+] LLM testing complete:")
            print(f"    - Files tested: {llm_tested}")
            print(f"    - Vulnerabilities found: {llm_found}")
            print(f"    - Time taken: {llm_duration:.2f}s")
            logging.info(f"[LLM] Batch testing complete: {llm_tested} tested, {llm_found} vulnerabilities found, {llm_duration:.2f}s")
        
        # 重新计算总时间（包括LLM测试）
        final_end_time = time.time()
        final_total_runtime = final_end_time - start_time
        
        print(f"[*] Total runtime: {final_total_runtime:.4f} seconds")
        logging.info(f"[*] Total runtime: {final_total_runtime:.4f} seconds")
        logging.info(f"[*] Total thread time: {total_thread_time:.4f} seconds")
        results["testing_duration"] = final_total_runtime
        save_output(results, result_file)
