# -*- coding:utf-8 -*-

from bs4 import BeautifulSoup
import urllib2
import chardet
import re
import sys
leak_url="http://www.wooyun.org/bugs/wooyun-2016-0226060"
#leak_url="http://www.wooyun.org/bugs/wooyun-2016-0226074"
def simplify_str(str):
    if str.find("http://www.",0)>-1:
        str=str.replace("http://www.","",1)
    elif str.find("https://www.",0)>-1:
        str=str.replace("https://www.","",1)
    elif str.find("http://",0)>-1:
        str=str.replace("http://","",1)
    elif str.find("https://",0)>-1:
        str=str.replace("https://","",1)
    elif str.find("www.",0)>-1:
        str=str.replace("www.","")
    str=str.replace("/","",1)
    return str
def search(key_word):
    url = "http://www.baidu.com/s?wd=" + urllib2.quote(key_word.decode(sys.stdin.encoding).encode('gbk'))
    print url
    try:
        html_text= urllib2.urlopen(url,timeout=25).read()
    except:
        return ""
    print html_text
    result1=re.search('官网'.decode('gb2312')+'[\s\S]*?((class="c-showurl)|(class="dv9rhdq-site"))".*',html_text,re.M)
    print result1	
    if result1 is not None:
        result1.group()
        str1=result1.group(0)
    else:
        return ""
    result2=re.search('((class="c-showurl)|(class="dv9rhdq-site")).*?(([a-zA-Z]+\.[0-9a-zA-Z]+\.[a-zA-Z]+\.[a-zA-Z]+)|([a-zA-Z]+\.[0-9a-zA-Z]+\.[a-zA-Z]+))',str1)
    if result2 is not None:
        result2.group()
        str2=result2.group(0)
    else:
        return "" 
    result3=re.search('(([a-zA-Z]+\.[0-9a-zA-Z]+\.[a-zA-Z]+\.[a-zA-Z]+)|([a-zA-Z]+\.[0-9a-zA-Z]+\.[a-zA-Z]+))',str2)
    if result3 is not None:
        result3.group()
        str_url=result3.group(0)
        str_url=simplify_str(str_url)
        return str_url
    else:
        return ""

refer = str(leak_url)
source = "10"
other_id = "WooYun-"+str(leak_url.split("wooyun-")[1].strip())
print other_id

request=urllib2.Request(url=leak_url.strip())
response=urllib2.urlopen(request,timeout=600)
response_text=response.read()
soup1 = BeautifulSoup(response_text, "html5lib")
tag1_list= soup1.find_all('h3','wybug_title')
print tag1_list
print chardet.detect(str(tag1_list[0]))
print chardet.detect("漏洞标题：")
s=str(tag1_list[0]).split(("漏洞标题：").decode('gb2312').encode('utf-8'))
print len(s)
print "============"
if len(tag1_list)> 0:
	name =str(tag1_list[0]).split(("漏洞标题：").decode('gb2312').encode('utf-8'))[1].strip().split("<")[0].strip()
	print "name ",name
	
tag1_list=soup1.find_all('h3','wybug_corp')
if len(tag1_list)> 0:
	print str(tag1_list[0])
	print str(tag1_list[0]).split(">")
	print str(tag1_list[0]).split(">")[2].split("<")[0]
	vendor = str(tag1_list[0]).split(">")[2].split("<")[0].strip()
	print "vendor ", vendor
	
print "=-------------------------------------------==========="
herf=soup1.find_all('h3','wybug_corp')
print chardet.detect(str(herf[0]))
print str(herf[0]).decode('utf-8')
tag2=herf[0].find('a')
print "=-------------------------------------------==========="
print tag2
print type(tag2)
print tag2.find('a','href')

print "=-------------------------------------------==========="
print tag2['href'].encode('UTF-8')
print tag2
source_name=tag2.get_text().encode('UTF-8')

print "source_name",source_name

source_url_str=tag2['href'].encode('UTF-8')
source_html= urllib2.urlopen(source_url_str,timeout=15).read()

if source_html.find(("厂商不存在或未通过审核").decode('gb2312').encode('utf-8')) == -1 :
	soup2=BeautifulSoup(source_html, "html5lib")
	tag3_list=soup2.find_all('h3',text=re.compile(".+\w+://\w+\.\w+.*?"))
	print tag3_list
	print type(tag3_list)

	print tag3_list[0]
	tag3=tag3_list[0]
	url_text=tag3.get_text().encode('UTF-8')
	url_str_list=re.search('\w+://\w+\.\w+.*',url_text)
	if url_str_list is not None:
		url_str=url_str_list.group(0)
		print url_str
		url_str=simplify_str(url_str)
		print '    url_str:　'+url_str
		ret_source_url = url_str

print source_name
print "1111111111111111111111111111111111"
url_str=search(source_name)
print url_str
