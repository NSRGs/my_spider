# -*- coding:utf8 -*-
import urllib2
import re
import chardet
import time
import datetime
page=1
url="http://www.wooyun.org/bugs/page/%s"%page
request=urllib2.Request(url=url)
response=urllib2.urlopen(request,timeout=600)
response_text=response.read()

wuyunid_pattern_str=re.compile(r'<td><a href="(.*?)">(.*?)</a>')
wuyunid_text=wuyunid_pattern_str.findall(response_text)
ret_wuyunid_list=[]
print type(wuyunid_text)

for lines in wuyunid_text:
	print lines[0]
	print lines[1].decode('utf-8')
	wuyunid = lines[0].split("wooyun-")[1]
	print lines[0].split("wooyun-")
#	print isinstance(lines[1],unicode)
#	print isinstance(lines[1],str)
#	print chardet.detect(lines[1])
        if wuyunid not in ret_wuyunid_list:
            ret_wuyunid_list.append(wuyunid)
    
#print ret_wuyunid_list
base_url= "http://www.wooyun.org/bugs/wooyun-"
for id in ret_wuyunid_list:
	real_url=base_url+id
	print real_url

print real_url
now=datetime.datetime.now()
print now
#(id,name,type,cve_id,bugtraq_id,other_id,cvss,refer,date,vendor,source,vuln_desc,near_threatened,nsfocus_id,osvdb_id,edb_id,version,solution,vendor_state,threat_type,threat_key,threat_system,threat_summary,source_url,db_product_type,db_Update_time,db_Leak_insert_time,db_Leak_reference,tvr_id,db_product,db_software_version)=("Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown","Unknown")

leak_url=real_url
refer = str(leak_url)
source = "10"
other_id = "WooYun-"+str(leak_url.split("wooyun-")[1].strip())