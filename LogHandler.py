import re
from collections import defaultdict, OrderedDict

class LogHandler(object):
    def __init__(self, access_log_path):
        self.access_log_path = access_log_path

    def __get_lines_from_log(self):
        with open(self.access_log_path) as f:
            content = f.readlines()
        return content
    
    def get_top_by_cookie(self, cookie_re, top=10):
        """Get TOP n cookie, re format is 'cookie=value'"""
        content = self.__get_lines_from_log()
        cookie_ip = defaultdict(list)
        for line in content:
            ip = line.split(' ', 1)[0]
            if ip[:3] != '10.':
                cookie = re.findall(cookie_re, line)
                if cookie: 
                    cookie = cookie[0].split('=', 1)[1]
                    cookie_ip[cookie].append(ip)
        top_list = OrderedDict()
        for cookie in sorted(cookie_ip, key=lambda cookie: len(cookie_ip[cookie]), reverse=True):
            if len(top_list) >= top:
                break
            top_list[cookie] = cookie_ip[cookie]
        return top_list

    def get_top_by_url(self, url_re, top=10):
        """Get TOP n ip by URL regexp"""
        content = self.__get_lines_from_log()
        ip_url = defaultdict(list)
        for line in content:
            ip = line.split(' ', 1)[0]
            if ip[:3] != '10.':
                try:
                    url = line.split('"', 2)[1].split(' ', 2)[1]
                except:
                    continue
                if re.search(url_re, url):
                    ip_url[ip].append(url)
        top_list = OrderedDict()
        for ip in sorted(ip_url, key=lambda ip: len(ip_url[ip]), reverse=True):
                if len(top_list) >= top:
                    break
                top_list[ip] = ip_url[ip]
        return top_list
                
    def get_top_by_requests_count(self, top=10):
        content = self.__get_lines_from_log()
        ip_rt = defaultdict(list)
        for line in content:
            ip = line.split(' ', 1)[0]
            if ip[:3] != '10.':
                rt = re.search(r"rt=\d{1,3}\.\d{3}", line)
                if rt:
                    rt = rt.group(0)
                    if isinstance(rt, str):
                        rt = float(rt.split('=')[1])
                        ip_rt[ip].append(rt)
        top_list = OrderedDict()
        for ip in sorted(ip_rt, key=lambda ip: len(ip_rt[ip]), reverse=True):
            if len(top_list) >= top:
                break
            top_list[ip] = ip_rt[ip]
        return top_list

    def get_top_by_status_code(self, code_re, top=10):
        content = self.__get_lines_from_log()
        ip_code = defaultdict(list)
        for line in content:
            try:
                ip = line.split(' ', 1)[0]
                if ip[:3] != '10.':
                    code = line.split('"')[2].split(' ')[1]
                    if re.match(code_re, code):
                        ip_code[ip].append(code)
            except:
                continue
        top_list = OrderedDict()
        for ip in sorted(ip_code, key=lambda ip: len(ip_code[ip]), reverse=True):
            if len(top_list) >= top:
                break
            top_list[ip] = ip_code[ip]
        return top_list
    
    def get_top_by_ua(self, ua_re):
        content = self.__get_lines_from_log()
        ip_ua = defaultdict(list)
        for line in content:
            try:
                ip = line.split(' ', 1)[0]
                if ip[:3] != '10.':
                    ua = line.split('"')[5]
                    if re.match(ua_re, ua):
                        ip_ua[ip].append(ua)
            except:
                continue
        top_list = OrderedDict()
        for ip in sorted(ip_ua, key=lambda ip: len(ip_ua[ip]), reverse=True):
            top_list[ip] = ip_ua[ip]
        return top_list
        
