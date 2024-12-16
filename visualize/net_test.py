import threading
import requests
import time
import random
import string

SEARCH_URL = "https://httpbin.org/post"  # 用于测试的 HTTP 接口
THREAD_COUNT = 10
DURATION = 60
SLEEP_TIME = 0.5

def generate_large_data(size_in_kb):
    """生成大约指定大小的随机数据（单位：KB）"""
    size = size_in_kb * 1024
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size))

def send_large_post():
    """发送大数据 POST 请求"""
    large_data = generate_large_data(500)  # 生成 500KB 的数据
    try:
        response = requests.post(SEARCH_URL, data=large_data, timeout=5)
        print(f"[{threading.current_thread().name}] POST status {response.status_code}")
    except requests.RequestException as e:
        print(f"[{threading.current_thread().name}] POST error: {e}")

def worker():
    while True:
        send_large_post()
        time.sleep(SLEEP_TIME)

def start_threads(thread_count):
    threads = []
    for i in range(thread_count):
        thread = threading.Thread(target=worker, name=f"Thread-{i}")
        thread.daemon = True
        threads.append(thread)
        thread.start()
    return threads

if __name__ == "__main__":
    print(f"Starting {THREAD_COUNT} threads to send large POST data for {DURATION} seconds...")
    threads = start_threads(THREAD_COUNT)
    start_time = time.time()
    try:
        while time.time() - start_time < DURATION:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Interrupted by user.")
    print("Finished sending POST requests.")
