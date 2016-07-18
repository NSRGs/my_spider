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
	url = "https://www.freebsd.org/security/advisories.html"
	freebsd = get_html(url)
	pattern = re.compile(r'<td class="txtdate" rowspan="1" colspan="1">(.*?)</td><td rowspan="1" colspan="1"><a href="//security.FreeBSD.org(.*?)" shape="rect">')
	list = pattern.findall(freebsd)
	return list

def get_vulnerability_info(temp_url):
	base_url = "https://www.freebsd.org/security"
	url = base_url + temp_url
	html = get_html(url)
	CVE_ID_pattern = re.compile(r'^CVE Name:(.*?)$',re.M)
	try :
		CVE_ID = CVE_ID_pattern.findall(html)[0].strip()
	except :
		CVE_ID = ""	
	Topic_pattern = re.compile(r'^Topic:(.*?)$',re.M)
	try :
		Topic = Topic_pattern.findall(html)[0].strip()
	except :
		Topic = ""	
	Affects_pattern = re.compile(r'^Affects:(.*?)$',re.M)
	try :
		Affects = Affects_pattern.findall(html)[0].strip()
	except :
		Affects = ""	
	Announced_pattern = re.compile(r'^Announced:(.*?)$',re.M)
	try :
		Announced = Announced_pattern.findall(html)[0].strip()
	except :
		Announced = ""	
	vulnerability = {}
	vulnerability['id'] = CVE_ID
	vulnerability['name'] = Topic
	vulnerability['level'] = ""
	vulnerability['time'] = Announced
	vulnerability['influence'] = Affects
	return vulnerability
def get_dead_time():
	try:
		f=open('dead_time','r')
		time = f.readline()
		f.close()
		return time
	except:
		return "2016-01-01"
def update_dead_time(new_time):
	print "update_dead_time : ",new_time
	f=open('dead_time','w')
	f.write(new_time)
	f.close()	
	return ""	
	
def vulnerability_info_save(info):
	f=open('freebsd_Security_Advisory.txt','a')
	for x in info:
		f.write(str(x)+'\n')		
	f.close()	

def get_info():	
	list=get_base_time_url()
	base_url = "https://www.freebsd.org/security"
	info = []
	dead_time = get_dead_time()
	new_time = dead_time
	for time,temp_url in list:
		if time > dead_time:
			print base_url+temp_url
			info.append(get_vulnerability_info(temp_url))
			if  new_time < time:
				new_time = time
	if new_time > dead_time:
		update_dead_time(new_time)
	return info
if  __name__ == '__main__' :
	info = get_info()
	vulnerability_info_save(info)


