# -*- coding : utf-8 -*-
import urllib2
import re
from bs4 import BeautifulSoup
def get_html(url):
	request = urllib2.Request(url)
	try:
		html = urllib2.urlopen(request,data = None,timeout=3).read()
		return html
	except:
		print "url: %s timeout"%url
		return None

def get_base_time_url():
	url = "http://struts.apache.org/docs/security-bulletins.html"
	apache = get_html(url)
	if apache is None:
		print "base url time out %s"%url
		return []
	pattern = re.compile(r'<a shape="rect" href="(.*?)">(.*?)</a>')
	apache_list = pattern.findall(apache)
	return apache_list
	
def get_vulnerability_info(temp_url,Id):
	base_url = "http://struts.apache.org/docs/"
	url = base_url + temp_url
	html = get_html(url)
	if html is None:
		return "%s error"%url
	soup = BeautifulSoup(html,"html5lib")
	soup.find(attrs={"id":"ConfluenceContent"})
	a= soup.find(attrs={"class":"table-wrap"})
	b= a.find_all(attrs={"class":"confluenceTh"})
	c = a.find_all(attrs={"class":"confluenceTd"})
	d={}
	for i in range(len(b)):
		d[b[i].string] = c[i].get_text()
		

	p_name = soup.find(attrs={"id":"ConfluenceContent"}).findAll('p')
	name = p_name[1].get_text()
	#if len(name) <5:
	#	name=p_name[1].get_text()
	try :
		CVE_ID = d['CVE Identifier']
	except :
		CVE_ID = ""
		
	try :
		level = d['Maximum security rating']
	except :
		level = ""
		
	try :
		Affected_Software = d['Affected Software']
	except :
		Affected_Software = ""
		
	try :
		Recommendation = d['Recommendation']
	except :
		Recommendation = ""

	vulnerability = {}
	vulnerability['id'] = CVE_ID
	vulnerability['name'] = name
	vulnerability['level'] = level
	vulnerability['time'] = Id
	vulnerability['influence'] = (Affected_Software +'.'+ Recommendation).strip()
	
	return vulnerability
def get_dead_time():
	try:
		f=open('dead_time','r')
		time = f.readline()
		f.close()
		return time
	except:
		return "S2-000"
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
	base_url = "http://struts.apache.org/docs/"
	info = []
	dead_Id = get_dead_time()
	new_Id = dead_Id
	for temp_url,Id in url_list:
		if Id > dead_Id:
			print base_url+temp_url
			info.append(get_vulnerability_info(temp_url,Id))
			if  new_Id < Id:
				new_Id = Id
	if new_Id > dead_Id:
		update_dead_time(new_Id)
	return info
if  __name__ == '__main__' :
	info = get_info()
	vulnerability_info_save(info)


