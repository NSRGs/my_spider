# -*- coding : utf-8 -*-
import urllib2
import re
from bs4 import BeautifulSoup
def get_html(url):
	request = urllib2.Request(url)
	html = urllib2.urlopen(request,data=None,timeout=3).read()
	if html is None:
		print "this url: %s timeout"%url
	return html
def get_base_time_url():
	url = "https://helpx.adobe.com/security.html"
	adobe = get_html(url)
	pattern = pattern = re.compile(r'APS.*?<a href="(.*?)".*?>.*?</a></td>[\s\S]*?\d*?/\d*?/\d*?<[\s\S]*?(\d*?)/(\d*?)/(\d*?)<')
	list = pattern.findall(adobe)
	return list

def get_vulnerability_info(temp_url):
	base_url = "https://helpx.adobe.com"
	url = base_url + temp_url
	if "http" in temp_url:
		url = temp_url
	print url
	try:
		html = get_html(url)
	except:
		print "can not open url%s"%url
		return {}
	CVE_ID_pattern = re.compile(r'^CVE number:.*?CVE(.*?)</p>',re.M)
	try :
		CVE_ID = "CVE" + CVE_ID_pattern.findall(html)[0].strip()
	except :
		CVE_ID = ""	
	Topic_pattern = re.compile(r'<div class="header">[\s\S]*?>$([\s\S]*?)</h3>',re.M)
	try :
		Topic = Topic_pattern.findall(html)[0].strip()
	except :
		Topic = ""	
		
	soup = BeautifulSoup(html,"html5lib")
	a= soup.find(attrs={"class":"parbase section table"})
	affect = ""
	if a is not None:
		affect = []
		tag_list=[]
		table_tag = a.find_all("th")
		for i in table_tag:
			tag_list.append(i.get_text())

		table_body = a.find_all("td")
		body_list=[]
		for i in table_body:
			body_list.append(i.get_text())
		
		i=0
		while i < len (body_list):
			if body_list[i] == body_list[i+1]:
				i=i+len (tag_list)
				continue
			temp = {}
			for j in range(len(tag_list)):
				temp[tag_list[j]]=table_body[i+j]
			#print temp
			affect.append(temp)
			i=i+len (tag_list)	
	
	Announced_pattern = re.compile(r'<strong>Release date:</strong>(.*?)</p>')
	try :
		Announced = Announced_pattern.findall(html)[0].strip()		
	except :
		Announced = ""	
	if "&nbsp;" in Announced:
		Announced = Announced.split('&nbsp;')[1]
	vulnerability = {}
	vulnerability['id'] = CVE_ID
	vulnerability['name'] = Topic
	vulnerability['level'] = ""
	vulnerability['time'] = Announced
	vulnerability['influence'] = affect
	print vulnerability
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
	f=open('adobe_Security_Advisory.txt','a')
	for x in info:
		f.write(str(x)+'\n')		
	f.close()	

def get_info():	
	list=get_base_time_url()
	base_url = "https://helpx.adobe.com"
	info = []
	dead_time = get_dead_time()
	
	new_time = dead_time
	for temp_url,month,day,year in list:
		#print temp_url,month,day,year
		#continue
		updated_time =  year+'-'+month+'-'+day
		if updated_time > dead_time:
			info.append(get_vulnerability_info(temp_url))
			if  new_time < updated_time:
				new_time = updated_time
	if new_time > dead_time:
		update_dead_time(new_time)
	return info
if  __name__ == '__main__' :
	info = get_info()
	vulnerability_info_save(info)
	#temp_url = "/content/help/en/security/products/flash-player/apsa16-03.html"
	#print get_vulnerability_info(temp_url)
	


