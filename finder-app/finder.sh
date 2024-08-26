#!/bin/bash

if [ $# -ne 2 ]; then
	echo "Wrong number of arguments"
	exit 1
fi

filesdir=$1
searchstr=$2

if ! [ -d $filesdir ]; then
	echo "filesdir does not represent a directory"
	exit 1
fi

numfiles=$(find $filesdir -type f | wc -l)
nummatch=$(grep -r $searchstr $filesdir | wc -l)

echo "The number of files are $numfiles and the number of matching lines are $nummatch"
