#!/bin/sh
ping $1 \
	| while IFS= read -r line; do printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line"; done \
	| sed 1d
