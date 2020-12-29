#!/bin/bash

grep "\-PROD\|$1" /app/jet/scripts/klassen/psaccesslog.txt | awk '{print $1 " " $6;}' > /app/jet/scripts/klassen/$1.txt