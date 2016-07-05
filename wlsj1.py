# -*- coding : utf-8 -*- 
from urllib import urlopen
from bs4 import BeautifulSoup
url="http://www.pythonscraping.com/pages/warandpeace.html"
html = urlopen(url).read()

bs_obj=BeautifulSoup(html, "html5lib")
print bs_obj
name_list=bs_obj.findAll("span",{"class":"green"})
final_list=[]
for name in name_list:
	final_list.append(name.string)
	final_list.append(name.get_text())
print final_list
print bs_obj


a=bs_obj.findAll(text="Heavens! what a virulent attack!")
print a
bs_obj.findAll(id="text")