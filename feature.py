import pandas as pd
import numpy as np
import os.path
import re 
from tld import get_tld
from urllib.parse import urlparse
from typing import Union

class FeatureExtraction:
    status = []

    def __init__(self,url):
    
        self.status = []
        self.url = url

        self.status.append(self.no_of_dir())
        self.status.append(self.no_of_embedi())
        self.status.append(self.httpSecure())
        self.status.append(self.abnormal_url())
        self.status.append(self.digit_count())
        self.status.append(self.letter_count())
        self.status.append(self.Shortining_Service())
        self.status.append(self.having_ip_address())
        self.status.append(self.count_dot())
        self.status.append(self.count_atrate())
        self.status.append(self.count_per())
        self.status.append(self.count_ques())
        self.status.append(self.count_hyphen())
        self.status.append(self.count_equal())
        self.status.append(self.url_len())
        self.status.append(self.hostname_len())
        self.status.append(self.subdomain_len())
        self.status.append(self.url_path_len())
        self.status.append(self.fld_length())
        self.status.append(self.tld_length())


    def url_len(self):
        x = len(str(self.url))
        return x
    

    def hostname_len(self):
        x = len(urlparse(self.url).netloc)
        return x


    def no_of_dir(self):
        urldir = urlparse(self.url).path
        return urldir.count('/')


    def no_of_embedi(self):
        urldir = urlparse(self.url).path
        return urldir.count('//')


    def process_tld1(self):
        try:
            res = get_tld(self.url, as_object = True, fail_silently=False,fix_protocol=True)
            pri_domain= res.domain
        except :
            pri_domain= None
        return pri_domain


    def process_tld2(self):
        try:
            res = get_tld(self.url, as_object = True, fail_silently=False,fix_protocol=True)
            pri_subdomain= res.subdomain
        except :
            pri_subdomain= None
        return pri_subdomain


    def subdomain_len(self):
        return len(str(self.url))
            

    def url_path_len(self):
        return len(str(self.url))
    

    #First Directory Length
    def fld_length(self):
        urlpath = urlparse(self.url).path
        try:
            return len(urlpath.split('/')[1])
        except:
            return 0


    def tld_length(self):
        try:
            return len(self.tld)
        except:
            return -1


    #imp imp df['url'] = df['url'].replace('www.', '', regex=True)

    def httpSecure(self):
        htp = urlparse(self.url).scheme
        match = str(htp)
        if match=='https':
            # print match.group()
            return 1
        else:
            # print 'No matching pattern found'
            return 0


    def count_dot(self):
        return self.url.count('.')
         

    def count_atrate(self):
        
        return self.url.count('@')


    def count_per(self):
        return self.url.count('%')


    def count_ques(self):
        return self.url.count('?')


    def count_hyphen(self):
        return self.url.count('-')


    def count_equal(self):
        return self.url.count('=')


    def abnormal_url(self):
        hostname = urlparse(self.url).hostname
        hostname = str(hostname)
        match = re.search(hostname, self.url)
        if match:
            # print match.group()
            return 1
        else:
            # print 'No matching pattern found'
            return 0
            

    def digit_count(self):
        digits = 0
        for i in self.url:
            if i.isnumeric():
                digits = digits + 1
        return digits

    def letter_count(self):
        letters = 0
        for i in self.url:
            if i.isalpha():
                letters = letters + 1
        return letters


    def Shortining_Service(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                        'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                        'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                        'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                        'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                        'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                        'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                        'tr\.im|link\.zip\.net', self.url)
                    
        if match:
            return 1
        else:
            return 0


    def having_ip_address(self):
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4 with port
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
            '([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
            '((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)', self.url)  # Ipv6
        if match:
            return 1
        else:
            return 0
        

    def getFeaturesList(self):
        return self.status
