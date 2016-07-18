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
def get_month_list(temp_url):
	base_url = "https://lists.apple.com"
	url = base_url+temp_url
	html = get_html(url)
	if html is 	None:
		print "month url time out %s"url
		return []
	month_pattern = re.compile(r'<li><strong><a name=".*?" href="(.*?)">APPLE-SA-(\d*?)-(\d*?)-(\d*?)-.*?</a></strong>')
	month_list = month_pattern.findall(html)
	list =[]
	for i in month_list:
		print i,temp_url
		list.append([temp_url +'/' + i[0],i[1]+'-'+i[2]+'-'+i[3]])
	return list

def get_base_time_url():
	url = "https://lists.apple.com/archives/security-announce/2016"
	apple = get_html(url)
	if apple is None:
		print "base url time out %s"url
		return []
	pattern = re.compile(r"<a href='(.*?)'>.*?</a><br>")
	list = pattern.findall(apple)
	month_list = []
	for temp_url in list:
		month_list += get_month_list(temp_url)
	return month_list

def get_vulnerability_info(temp_url,date):
	base_url = "http://lists.apple.com"
	url = base_url + temp_url
	html = get_html(url)
	if html is None:
		return []
	body_pattern = re.compile(r'BEGIN PGP SIGNED MESSAGE-*?$([\s\S]*?)BEGIN PGP SIGNATURE',re.M)
	body = body_pattern.findall(html)[0].strip()
	vulnerability_pattern = re.compile(r'^(.*?)\nAvailable for:([\s\S]*?\n\n)',re.M)
	v=	vulnerability_pattern.findall(body)
	vulnerability_list = []
	Topic_pattern = re.compile(r'<title>(.*?)</title>')
	try :
		Topic = Topic_pattern.findall(html)[0].strip()
	except :
		Topic = ""
	for name,item in v:
		print name,item
		CVE_ID_pattern = re.compile(r'^(CVE-\d*?-\d*?) :',re.M)
		try :
			CVE_ID=	CVE_ID_pattern.findall(item)
		except :
			CVE_ID = []	
		vulnerability = {}
		vulnerability['id'] = CVE_ID
		vulnerability['name'] = name
		vulnerability['level'] = ""
		vulnerability['time'] = 0
		vulnerability['influence'] = Topic
		vulnerability_list.append(vulnerability)
	return vulnerability_list
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
	f=open('apple_Security_Advisory.txt','a')
	for x in info:
		f.write(str(x)+'\n')		
	f.close()	

def get_info():	
	list=get_base_time_url()
	base_url = "http://lists.apple.com"
	info = []
	dead_time = get_dead_time()
	new_time = dead_time
	for temp_url,time0 in list:
		if time0 > dead_time:
			print base_url+temp_url
			info+=get_vulnerability_info(temp_url,time0)
			if  new_time < time0:
				new_time = time0
	if new_time > dead_time:
		update_dead_time(new_time)
	return info
if  __name__ == '__main__' :
	info = get_info()
	vulnerability_info_save(info)


