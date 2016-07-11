# -*- coding:utf8 -*-
import urllib2
import re
def get_html(url):
	request = urllib2.Request(url=url)
	response = urllib2.urlopen(request)
	html = response.read()
	return html
#print html
def get_Security_Advisory_list(url):
	html = get_html(url)
	pattern = re.compile(r'<a href="(.*?)">Security Advisory</a>')
	list = pattern.findall(html)
	return list

def get_Security_Advisory_info(url,info):
	print "====================="
	print url
	html = get_html(url)
	id_pattern = re.compile(r'^(.*?)\(CVE(.*?)\)$',re.M)
	id_list = id_pattern.findall(html)

	Severity_pattern = re.compile(r'^Severity: (.*?)$',re.M)
	Severity_level=Severity_pattern.findall(html)
	print 
	print len(Severity_level)
	print len(id_list)
	text_pattern = re.compile(r'^Severity:([\s\S]*?)^===',re.M)
	text = text_pattern.findall(html)
	
	influence_pattern = re.compile(r'^(.*?)users should upgrade to(.*?)$',re.M)
	for i in range(len(id_list)):
		vulnerability = {}
		vulnerability['id'] = 'CVE' + id_list[i][1]
		vulnerability['name'] = id_list[i][0]
		vulnerability['level'] = Severity_level[i]		
		vulnerability['influence'] = []
		influence = influence_pattern.findall(text[i])
		for data in influence:
			influence_str = data[0] + 'users should upgrade to' + data[1]
			vulnerability['influence'].append(influence_str)
		info.append(vulnerability)
#	return info
	
def get_info():
	url = "https://www.openssl.org/news/newslog.html"
	list = get_Security_Advisory_list(url)
	print list
	ori_url = "https://www.openssl.org"
	info = []
	for append_url in list:
		txt_url = ori_url + append_url
		get_Security_Advisory_info(txt_url,info)
	return info
if __name__ == '__main__':
	info = get_info()
	for x in info:
		print x