#! /bin/bash

firstarg=$(git log 2> /dev/null | head -1 | awk '{print $1}')
if [ "x$firstarg" == "xcommit" ]; then
	gver=$(git log | head -1 | awk '{print $2}' | cut -b 1-7)
	echo -n -DMLX5_GITVER="$gver"
fi


