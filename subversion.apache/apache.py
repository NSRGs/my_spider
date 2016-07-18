# -*- coding : utf-8 -*-
import urllib2
import re

def get_html(url):
	request = urllib2.Request(url)
	try:
		html = urllib2.urlopen(request,data = None,timeout=3).read()
		return html
	except:
		print "url: %s timeout"%url
		return None

def get_base_time_url():
	url = "http://subversion.apache.org/security/"
	apache = get_html(url)
	if apache is None:
		print "base url time out %s"%url
		return []
	pattern = re.compile(r'<td><a href="CVE.*?">(CVE-\d*-\d*)-advisory.txt</a></td>\n<td>(.*?)</td>\n<td>(.*?)</td>')
	apache_list = pattern.findall(apache)
	apache_list
	return apache_list
def get_dead_time():
	try:
		f=open('dead_time','r')
		time = f.readline()
		f.close()
		return time
	except:
		return "2015-01-01"
def update_dead_time(new_time):
	print "update_dead_time : ",new_time
	f=open('dead_time','w')
	f.write(new_time)
	f.close()	
	return ""	
	
def vulnerability_info_save(info):
	f=open('apache_Security_Advisory.txt','a')
	for x in info:
		f.write(str(x)+'\n')		
	f.close()	

def get_info():	
	url_list=get_base_time_url()
	base_url = "http://subversion.apache.org/security/"
	info = []
	dead_time = get_dead_time()
	new_time = dead_time
	for CVE_ID,influence,name in url_list:
		if CVE_ID > dead_time:
			vulnerability = {}
			vulnerability['id'] = CVE_ID
			vulnerability['name'] = name
			vulnerability['level'] = ""
			vulnerability['time'] = ""
			vulnerability['influence'] = influence
			print vulnerability
			info.append(vulnerability)
			if  new_time < CVE_ID:
				new_time = CVE_ID
	if new_time > dead_time:
		update_dead_time(new_time)
	return info
if  __name__ == '__main__' :
	info = get_info()
	vulnerability_info_save(info)


