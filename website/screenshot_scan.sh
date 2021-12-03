#!/bin/bash


if [ ! -n "$1" ] || [! -n "$2"]; then
    echo "Usage: ./sreenshot_scan.sh <--domain/--cidr> <domain/cidr range> -p <ports> <--check>"
    exit 1
fi
target=$1

cd ./website/images/scans
mkdir $target
cd $target

if [ "$2" = "-p" ]; then
    gowitness scan --cidr $target -p $3 -t 50
else
    gowitness scan --cidr $target -t 50
fi

