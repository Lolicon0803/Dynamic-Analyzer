#!/bin/bash
# $1 IP
# $2 UUID

routerSploit="../rsf.py" #Change it
dir="$2" #Change it
logDir="$dir/dynamic" 
scanLog="$logDir/scanLog.txt"
execLog="$logDir/execLog.txt"

searchCmd="$logDir/searchCmd.txt"
cmd="cmd.txt"

if [ ! -d "$dir" ];then
mkdir $dir
mkdir $logDir
touch $scanLog
touch $execLog
fi

echo "making cmd..."
python3 log.py -cmd $logDir $1
echo "scanning..."
timeout -s SIGKILL 5m python3 $routerSploit < $cmd > $scanLog
echo "making log..."
python3 log.py -json $2 $1
echo "making exec cmd..."
python3 log.py -scan $logDir $1
echo "execusing..."
timeout -s SIGKILL 5m python3 $routerSploit < $searchCmd > $execLog

echo "finish."

#timeout -s SIGKILL 5m python3 rsf.py < log2.txt > log3.txt
#python3 log.py -b 192.168.0.1



