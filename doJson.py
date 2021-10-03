
import json


exploits_obj = {
    'time': 'Apple',
    'details': []
}

creds_obj = {
    'time': 'Apple',
    'details': []
}


STATUS = ['invulnerable', 'vulnerable', 'unable_verified', 'undefined']

with open(''.join(['test1/static', '/scanLog.txt']), 'r') as f:
    content_list = f.read().splitlines()

data = []


for c in content_list:

    d = c.split(' ')
    detail = dict()

    if c.find('is not vulnerable') != -1:
        detail['status'] = STATUS[0]
    elif c.find('Could not be verified') != -1:
        detail['status'] = STATUS[1]
    elif c.find('is vulnerable') != -1:
        detail['status'] = STATUS[2]
    else:
        detail['status'] = STATUS[3]
        continue

    detail['port'] = d[1][d[1].find(':')+1:]
    detail['service'] = d[2]
    detail['name'] = d[3]
    exploits_obj['details'].append(detail)


for c in content_list:

    d = c.split(' ')
    creds = dict()

    if c.find('Found default credentials') != -1:







