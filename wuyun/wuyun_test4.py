# -*- coding:utf-8 -*-

from bs4 import BeautifulSoup
import urllib2
import chardet
import re
source_url_str="http://www.wooyun.org/corps/靠靠靠靠靠"
print source_url_str
source_html= urllib2.urlopen(source_url_str,timeout=15).read()
print source_html
print chardet.detect(source_html)
print source_html.find(("厂商不存在或未通过审核").decode('gb2312').encode('utf-8'))


soup2=BeautifulSoup(source_html, "html5lib")
tag3_list=soup2.find_all('h3',text=re.compile(".+\w+://\w+\.\w+.*?"))
print tag3_list





