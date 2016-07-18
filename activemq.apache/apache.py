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
	url = "http://activemq.apache.org/security-advisories.data/"
	apache = get_html(url)
	if apache is None:
		print "base url time out %s"%url
		return []
	print 
	pattern = re.compile(r'<td><a href="(.*?)">.*?-announcement.txt</a></td><td align="right">(\d*-\d*-\d*).*?</td>')
	apache_list = pattern.findall(apache)
	return apache_list
	
def get_vulnerability_info(url,date):
	html = get_html(url)
	if html is None:
		return "%s error"%url
		
	name_pattern = re.compile(r'^(CVE-\d*-\d*): (.*?)$',re.M)
	level_pattern = re.compile(r'^Severity:(.*?)$',re.M)
	Versions_Affected_pattern = re.compile(r'^Versions Affected:\n^(.*?)$',re.M)	
	Recommendation_pattern = re.compile(r'^Mitigation:\n^(.*?)$',re.M)
	
	try :
		name = name_pattern.findall(html)[0]
	except :
		name = ["",""]		
	try :
		level = level_pattern.findall(html)[0].strip()
	except :
		level = ""		
	try :
		Versions_Affected = Versions_Affected_pattern.findall(html)[0]
	except :
		Versions_Affected = ""		
	try :
		Recommendation = d['Recommendation']
	except :
		Recommendation = Recommendation_pattern.findall(html)[0]

	vulnerability = {}
	vulnerability['id'] = name[0]
	vulnerability['name'] = name[1]
	vulnerability['level'] = level
	vulnerability['time'] = date
	vulnerability['influence'] = (Versions_Affected +'.'+ Recommendation).strip()
	print vulnerability
	return vulnerability
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
	base_url = "http://activemq.apache.org/security-advisories.data/"
	info = []
	dead_time = get_dead_time()
	new_time = dead_time
	for temp_url,date in url_list:
		if date > dead_time:
			print base_url+temp_url
			info.append(get_vulnerability_info(base_url+temp_url,date))
			if  new_time < date:
				new_time = date
	if new_time > dead_time:
		update_dead_time(new_time)
	return info
if  __name__ == '__main__' :
	info = get_info()
	vulnerability_info_save(info)


