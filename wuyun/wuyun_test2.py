# -*- coding:utf8 -*-
import urllib2
import re

page=1
url="http://www.wooyun.org/bugs/page/%s"%page
request=urllib2.Request(url=url)
response=urllib2.urlopen(request,timeout=600)
response_text=response.read()

wuyunid_pattern_str=re.compile(r'<td><a href="(.*?)">(.*?)</a>')
wuyunid_text=wuyunid_pattern_str.findall(response_text)

print type(wuyunid_text)
for lines in wuyunid_text:
	print lines



print "¹þ¹þ"