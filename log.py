
import sys
import json
import re
import requests
import time

# sys.argv[1] -scan
# sys.argv[2] logDir
# sys.argv[3] ip

# sys.argv[1] -json
# sys.argv[2] logDir
# sys.argv[3] uuid
# sys.argv[4] user_id
# sys.argv[5] device_id


def target_only(exploit, ip):
    writeData.append('use '+exploit+'\n')
    writeData.append('set target '+ip+'\n')
    writeData.append('run'+'\n')


def shell_exit():
    writeData.append('exit'+'\n')


# 時間戳
create_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


if sys.argv[1] == '-cmd':
    with open('cmd.txt', 'w') as f:
        f.write("use scanners/autopwn\n")
        f.write(''.join(["set target ", sys.argv[3], '\n']))
        f.write("run\n")


if sys.argv[1] == '-scan':
    output = []
    writeData = []

    with open(''.join([sys.argv[2], '/scanLog.txt']), 'r') as f:
        content_list = f.read().splitlines()

    for content in content_list:
        if content.find("92m[+]") != -1 and content.find("Device") == -1 and content.find("=>") == -1:
            c = content.split(' ')
            output.append(c[3])

    for o in output:
        if str(o).find("exploits/routers/dlink/dir_8xx_password_disclosure") != -1:
            target_only(o, sys.argv[3])
        elif str(o).find("exploits/routers/dlink/multi_hnap_rce") != -1:
            target_only(o, sys.argv[3])
            shell_exit()
        elif str(o).find("exploits/routers/dlink/dir_850l_creds_disclosure") != -1:
            target_only(o, sys.argv[3])
        elif str(o).find("exploits/routers/dlink/dir_300_645_815_upnp_rce") != -1:
            target_only(o, sys.argv[3])
        elif str(o).find("exploits/routers/dlink/dir_300_320_615_auth_bypass") != -1:
            target_only(o, sys.argv[3])
        elif str(o).find("exploits/routers/linksys/eseries_themoon_rce") != -1:
            target_only(o, sys.argv[3])

    with open(''.join([sys.argv[2], '/searchCmd.txt']), 'w') as f:
        for w in writeData:
            f.write(w)


if sys.argv[1] == '-json':
    exploits_obj = {
        'details': []
    }

    creds_obj = {
        'details': []
    }

    json_obj = {
        'uuid': sys.argv[3],
        'user_id': sys.argv[4],
        'device_id': sys.argv[5],
        'status': "testing",
        'exploits_time': '-1',
        'creds_time': '-1',
        'created_at': create_time,
        'updated_at': '',
        'exploits': exploits_obj,
        'creds': creds_obj
    }

    STATUS = ['invulnerable', 'vulnerable', 'unable_verified', 'undefined']

    with open(''.join(['test1/static', '/scanLog.txt']), 'r') as f:
        content_list = f.read().splitlines()

    creds_data = []
    is_creds = False
    time_list = []

    for c in content_list:

        d = c.split(' ')
        exploits_detail = dict()
        creds_detail = dict()

        # 抓creds
        if c.find('Found default credentials') != -1:
            is_creds = True

        if is_creds:
            creds_data.append(c)

        # 抓time
        if c.find('Elapsed time') != -1:
            time_list.append(d[3])

        # 抓exploit
        if c.find('is not vulnerable') != -1:
            exploits_detail['status'] = STATUS[0]
        elif c.find('Could not be verified') != -1:
            exploits_detail['status'] = STATUS[1]
        elif c.find('is vulnerable') != -1:
            exploits_detail['status'] = STATUS[2]
            if(c.find('Device')):
                continue
        else:
            exploits_detail['status'] = STATUS[3]
            continue

        exploits_detail['port'] = d[1][d[1].find(':')+1:]
        exploits_detail['service'] = d[2]
        exploits_detail['name'] = d[3]
        exploits_obj['details'].append(exploits_detail)

    for c in creds_data:

        d = re.compile('[\S]+')
        e = re.compile('[\s]+')
        s = e.split(c)
        if(len(s) > 1 and s[0].find('[+]') == -1 and s[1].find('Target') == -1 and s[1].find('-') == -1):
            creds_detail['port'] = s[2]
            creds_detail['service'] = s[3]
            creds_detail['username'] = s[4]
            creds_detail['password'] = s[5]
            creds_obj['details'].append(creds_detail)

    if(len(time_list) == 1):
        json_obj['exploits_time'] = time_list[0]
    elif(len(time_list) == 2):
        json_obj['exploits_time'] = time_list[0]
        json_obj['creds_time'] = time_list[1]

    json_obj['updated_at'] = time.strftime(
        "%Y-%m-%d %H:%M:%S", time.localtime())

    with open(''.join([sys.argv[2], '/log.json']), 'w') as f:
        f.write(json.dumps(json_obj, indent=1))

    # call api
    api_str = "http://127.0.0.1/api/analyses/"+sys.argv[2]+"/dynamic"
    response = requests.post(api_str, json=json_obj)
    print("api response:"+response)


