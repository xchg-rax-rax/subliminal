#!/bin/bash

if [ ! -n "$1" ]; then
    echo "Usage: enumerate_subdomains.sh <domain> [-short|-long|-brute] [-threads n]\n"
    exit 1
fi
domain=$1
if [ "$3" = "-threads" ]; then
    threads=$4
else
    threads=10
fi
temp=$(mktemp)
if [ "$2" = "-short" ]; then
    subfinder -d $domain -t $threads -silent >$temp 2>/dev/null
elif [ "$2" = "-long" ];then
    subfinder -d $domain -all -t $threads -silent >$temp 2>/dev/null
    amass enum -d $domain >$temp 2>/dev/null
    assetfinder --subs-only $domain >$temp 2>/dev/null
elif [ "$2" = "-brute" ];then
    subfinder -d $domain -all -t $threads -silent >$temp 2>/dev/null
    amass enum -d $domain -active -brute > $temp 2>/dev/null
    assetfinder --subs-only $domain >$temp 2>/dev/null
else
    echo "Usage: enumerate_subdomains.sh <domain> [-short|-long|-brute] [-threads n]\n"
    exit 1
fi
cat $temp | grep $domain | grep "@" -v
exit 0
