#!/bin/bash

grep "\-PROD\|$1" /app/jet/scripts/klassen/psaccesslog.txt > /app/jet/scripts/klassen/$1.txt