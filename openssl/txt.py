# -*- conding:utf-8 -*-
import urllib2
import re

url = "https://www.openssl.org/news/secadv/20141015.txt"
url1 = "https://www.openssl.org/news/secadv/20140806.txt"
info = []
def get_Security_Advisory_info(url,info):
	print "====================="
	print url
	html_pattern = re.compile(r'Security Advisory(.*?)$([\s\S]*?)^References$',re.M)
	aa= id_pattern.findall(html)
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
		
		
get_Security_Advisory_info(url,info)		
print info