#!/bin/bash

for i in {01..22};
do ssh weblogic@atg-ps$i-prod 'sedtime=$(date --date "-10min" +"%d\/%b\/%Y:%H:%M:%S") && sed -n "/$sedtime/,$ p" /app/nginx/logs/atg-access.log' >> /app/jet/scripts/klassen/ps$i-accesslog.txt &
done
wait

for i in {01..22};
do printf "\n\n\n***PS$i-PROD***\n\n\n" >> /app/jet/scripts/klassen/psaccesslog.txt ; cat /app/jet/scripts/klassen/ps$i-accesslog.txt >> /app/jet/scripts/klassen/psaccesslog.txt ; rm -rf /app/jet/scripts/klassen/ps$i-accesslog.txt
done