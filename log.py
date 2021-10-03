
import sys
import json
import re

# sys.argv[1] -scan
# sys.argv[2] uuid/static
# sys.argv[3] ip


def target_only(exploit, ip):
    writeData.append('use '+exploit+'\n')
    writeData.append('set target '+ip+'\n')
    writeData.append('run'+'\n')

def shell_exit():
    writeData.append('exit'+'\n')

if sys.argv[1] == '-cmd':
    with open('cmd.txt', 'w') as f:
        f.write("use scanners/autopwn\n")
        f.write(''.join(["set target ",sys.argv[3],'\n']))
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
        if str(o).find("exploits/routers/dlink/dir_8xx_password_disclosure")!= -1:
            target_only(o, sys.argv[3])
        elif str(o).find("exploits/routers/dlink/multi_hnap_rce")!= -1:
            target_only(o, sys.argv[3])
            shell_exit()
        elif str(o).find("exploits/routers/dlink/dir_850l_creds_disclosure")!= -1:
            target_only(o, sys.argv[3])
        elif str(o).find("exploits/routers/dlink/dir_300_645_815_upnp_rce")!= -1:
            target_only(o, sys.argv[3])
        elif str(o).find("exploits/routers/dlink/dir_300_320_615_auth_bypass")!= -1:
            target_only(o, sys.argv[3])
        elif str(o).find("exploits/routers/linksys/eseries_themoon_rce")!= -1:
            target_only(o, sys.argv[3])
        

    with open(''.join([sys.argv[2], '/searchCmd.txt']), 'w') as f:
        for w in writeData:
            f.write(w)




if sys.argv[1]== '-json':
    exploits_obj = {
        'time': '-1',
        'details': []
    }

    creds_obj = {
        'time': '-1',
        'details': []
    }

    json_obj = {
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
        exploits_obj['time'] = time_list[0]
    elif(len(time_list) == 2):
        exploits_obj['time'] = time_list[0]
        creds_obj['time'] = time_list[1]


    with open(''.join([sys.argv[2], '/log.json']), 'w') as f:
        f.write(json.dumps(json_obj, indent=1))











'''
if sys.argv[1] == '-scan':
    output = []

    with open(''.join([sys.argv[2], '/scan.txt']), 'r') as f:
        content_list = f.read().splitlines()

    for content in content_list:
        if content.find("92m[+]") != -1 and content.find("Device") == -1 and content.find("=>") == -1:
            c = content.split(' ')
            output.append(c[3])

    with open(''.join([sys.argv[2], '/searchCmd.txt']), 'w') as f:
        for t in output:
            f.write("use "+t+"\n")
            f.write("show options\n")

'''

'''
elif sys.argv[1] == '-b':

    output = []
    flag = 0

    with open('log2.txt', 'r') as f:
        command_list = f.read().splitlines()

    with open('log3.txt', 'r') as f:
        content_list = f.read().splitlines()

    for content in content_list:

        if content.find("Target options") != -1:
            o = command_list.pop(0)
            if o.find("rce") != -1:
                flag = 1

            output.append(o)
            command_list.pop(0)

        if content.find("target") != -1:
            output.append("set target "+sys.argv[2])
            output.append("run")

            print(flag)
            if flag == 1:
                output.append("exit")

            flag = 0

    with open('log4.txt', 'w') as f:
        for t in output:
            f.write(t+"\n")
'''
