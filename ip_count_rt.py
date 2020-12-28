import re
from collections import defaultdict
import subprocess

subprocess.call(['rm', '/app/jet/scripts/klassen/psaccesslog.txt'])
subprocess.call(['sh', '/home/klassen/SWBlockBot/get_access_log_for_10min.sh'])


with open(r'/app/jet/scripts/klassen/psaccesslog.txt') as f:
    content = f.readlines()

ip_rt = defaultdict(list)
for line in content:
    ip = line.split(' ', 1)[0]
    rt = re.findall(r"rt=\d\.\d{3}", line)
    if rt:
        rt = rt[0]
    if not isinstance(rt, list):
        rt = float(rt.split('=')[1])
        ip_rt[ip].append(int(rt*1000))



for ip in sorted(ip_rt, key=lambda ip: len(ip_rt[ip]), reverse=True):
    if ip[:3] != '10.' and (len(ip_rt[ip]) > 500 or sum(ip_rt[ip])/len(ip_rt[ip]) > 10000):
        print("{}\t{}\t{}".format(ip, len(ip_rt[ip]), sum(ip_rt[ip])/len(ip_rt[ip])))


