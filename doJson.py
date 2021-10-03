
import json
import re


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


with open('t.json', 'w') as f:
    f.write(json.dumps(json_obj, indent=1))
# print(json_obj)
