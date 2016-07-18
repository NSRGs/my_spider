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
	pattern = re.compile(r'<tr><td class="d">(.*?)</td><td class="t"><a href="(.*?)">Security Advisory</a>')
	list = pattern.findall(html)
	return list

def get_Security_Advisory_info(url,info,event_time):
	print "====================="
	print url
	html = get_html(url)
	id_pattern = re.compile(r'^(.*?)\(CVE(.*?)\)$',re.M)
	id_list = id_pattern.findall(html)

	Severity_pattern = re.compile(r'^Severity: (.*?)$',re.M)
	Severity_level=Severity_pattern.findall(html)
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
		vulnerability['time'] = event_time
		vulnerability['influence'] = []
		influence = influence_pattern.findall(text[i])
		for data in influence:
			influence_str = data[0] + 'users should upgrade to' + data[1]
			vulnerability['influence'].append(influence_str)
		info.append(vulnerability)
#	return info
def get_month(month):
	month2num = {'Jan':'01','Feb':'02','Mar':'03','Apr':'04','May':'05','Jun':'06','Jul':'07','Aug':'08','Sep':'09','Oct':'10','Dec':'12','Nov':'11'}
	return month2num[month]
def get_normal_time(time_str,dead_time):
	pattern = re.compile(r'(.*?)-(.*?)-(.*?)$')
	time_ele = pattern.findall(time_str)[0]
	if time_ele[2] < "2013":
		return "time too old"
	month2num = {'Jan':'01','Feb':'02','Mar':'03','Apr':'04','May':'05','Jun':'06','Jul':'07','Aug':'08','Sep':'09','Oct':'10','Dec':'12','Nov':'11'}
	normal_time = time_ele[2]+"-"+month2num[time_ele[1]]+"-"+time_ele[0]
	if normal_time <= dead_time:
		return "time too old"
	return normal_time
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
def get_info():
	url = "https://www.openssl.org/news/newslog.html"
	list = get_Security_Advisory_list(url)
	print "++++++++++++++++++url time list+++++++++++++++++++++++++"
	print list
	ori_url = "https://www.openssl.org"
	info = []
	dead_time = get_dead_time()
	new_time = dead_time
	for time,append_url in list:
		event_time = get_normal_time(time,dead_time)
		if  event_time != "time too old":
			txt_url = ori_url + append_url
			get_Security_Advisory_info(txt_url,info,event_time)
			if event_time > new_time:
				new_time = event_time
	if new_time > dead_time:
		update_dead_time(new_time)
	return info
if __name__ == '__main__':
	info = get_info()
	print "===============information====================="
	print info
	f=open('Security_Advisory.txt','a')
	for x in info:
		print x
		f.write(str(x)+'\n')		
	f.close()	