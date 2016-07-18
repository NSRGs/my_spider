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
	url = "http://web.mit.edu/kerberos/advisories/"
	kerberos = get_html(url)
	pattern = re.compile(r'<DT><A HREF="(.*?)">MITKRB5-SA-(\d*?)-\d*?</A>')
	list = pattern.findall(kerberos)
	return list

def get_vulnerability_info(temp_url):
	base_url = "http://web.mit.edu/kerberos/advisories/"
	url = base_url + temp_url
	html = get_html(url)

	before_summary_pattern = re.compile(r'(^Topic:[\s\S]*?)SUMMARY',re.M)
	before_summary = before_summary_pattern.findall(html)[0]
	before_summary
	CVE_ID_pattern = re.compile(r'^(CVE.*?):(.*?)$',re.M)

	try :
		CVE_ID = CVE_ID_pattern.findall(before_summary)
	except :
		CVE_ID = []

	Announced_pattern = re.compile(r'^Last update:(.*?)$',re.M)
	try :
		Announced = Announced_pattern.findall(html)[0].strip()
	except :
		Announced = ""	

	AFFECTED_pattern = re.compile(r'^AFFECTED SOFTWARE\n=*?$([\s\S]*?)=====',re.M)
	AFFECTED  = AFFECTED_pattern.findall(html)[0] 

	Affects_pattern = re.compile(r'^CVE.*?:([\s\S]*?)\n\n',re.M)
	try :
		Affects = Affects_pattern.findall(AFFECTED)
	except :
		Affects = ""	
	i=0
	vulnerability_list = []
	for CVE,Topic in CVE_ID:
		vulnerability = {}
		vulnerability['id'] = CVE
		
		vulnerability['name'] = Topic
		vulnerability['level'] = ""
		vulnerability['time'] = Announced
		vulnerability['influence'] = Affects[i]
		i=i+1
		vulnerability_list.append(vulnerability)
	if CVE_ID == [] :
		vulnerability = {}
		vulnerability['id'] = ""
		Topic_pattern = re.compile(r'^Topic:(.*?)$',re.M)
		try :
			Topic = Topic_pattern.findall(html)[0]
		except :
			Topic = ""		
		vulnerability['name'] = Topic
		vulnerability['level'] = ""
		vulnerability['time'] = Announced
		vulnerability['influence'] = AFFECTED
		vulnerability_list.append(vulnerability)		
	return Announced,vulnerability_list
def get_dead_time():
	try:
		f=open('dead_time','r')
		time = f.readline()
		f.close()
		return time
	except:
		return "2013-01-01"
def update_dead_time(new_time):
	print "update_dead_time : ",new_time
	f=open('dead_time','w')
	f.write(new_time)
	f.close()	
	return ""	
	
def vulnerability_info_save(info):
	f=open('kerberos_Security_Advisory.txt','a')
	for x in info:
		f.write(str(x)+'\n')		
	f.close()	

def get_info():	
	list=get_base_time_url()
	base_url = "http://web.mit.edu/kerberos/advisories/"
	info = []
	dead_time = get_dead_time()
	new_time = dead_time
	for temp_url,time in list:
		print temp_url,time,time+"-12-31"
		if time+"-12-31" > dead_time:
			print base_url+temp_url
			data,vulnerability_list=get_vulnerability_info(temp_url)
			print vulnerability_list,data,new_time
			if data > dead_time:
				info.append(vulnerability_list)
			if  new_time < data:
				new_time = data
	if new_time > dead_time:
		update_dead_time(new_time)
	return info
if  __name__ == '__main__' :
	info = get_info()
	vulnerability_info_save(info)


