#!/bin/bash

if [ $# -ne 2 ]; then
	echo "Wrong number of arguments"
	exit 1
fi

writefile=$1
writestr=$2

mkdir -p $(dirname $writefile)
touch $writefile
if [ $? -ne 0 ]; then
	echo "Fail while creating a file."
	exit 1
fi
echo $writestr > $writefile
