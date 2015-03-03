import socket
import time
import ipaddress
import threading
import urllib.request
from urllib.parse import urlparse
import re
import queue as q
import collections
import sqlite3

def flatten(l):
    for el in l:
        if isinstance(el, collections.Iterable) and not isinstance(el, str):
            for sub in flatten(el):
                yield sub
        else:
            yield el

def filterIPsbyList(ip, filters):
	ip = ipaddress.IPv4Address(ip)
	for filter in filters:
		if filter[0] < ip < filter[1]:
			return ip
	return False
	
def appendToFile(input, filename):
	i = flatten(input)
	if input and isinstance(i, collections.Iterable):
		i = filter(None, i)
		i = list(set(i))
		input = '\n'.join(i)
	with open(filename+".txt", "a") as myfile:
		myfile.write(input+"\n")

def estIps():
	f = open("ee.csv")
	lines = f.readlines()
	estIps = []
	i=0
	for line in lines:
		a = line.split(",")
		estIps.append([ipaddress.IPv4Address(a[0]), ipaddress.IPv4Address(a[1])])
		i+=1
	return estIps

def sniff(filters):
	HOST = socket.gethostbyname(socket.gethostname())
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
	s.bind((HOST, 0))
	s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
	s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
	prev = "127.0.0.1"
	counter = 0
	while True:
		try:
			data = s.recvfrom(80)
			out = filterIPsbyList(data[1][0], filters)
			if out != False and out != prev:
				prev = out
				#print("Connected to: "+str(out))
				counter += 1
				unProcessedIPs.put(out.exploded)
				#appendToFile([out.exploded], "raw-ips")
		except:
			a = 0

	s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


def extractUrls(page):
	pat = re.compile(r'<cite\b[^>]*>(.*?)</cite>')
	urls = re.findall(pat, str(page))
	output = []
	for url in urls:
		output.append(url.split('/', 1)[0])
	return output
	
def getBingUrlsByIp(ip):
	ip = str(ip)
	urls = []
	finished = False
	i = 0
	while True:
		f = urllib.request.urlopen('http://www.bing.com/search?q=ip:'+ip+'&go=&count=50&FORM=QBHL&qs=n&first='+str((i*50)+1)).read()
		nextUrls = extractUrls(f)
		if i > 0:
			if not nextUrls:
				break
			try:
				a = nextUrls[-1]
				b = urls[-1]
			except:
				a = 0
				b = 1
		else:
			a = 0
			b = 1
		if  a == b:
			break
		else:
			urls.extend(nextUrls)
		i+=1
	#print(urls, len(urls))
	print("Got "+str(len(urls))+"urls from "+ip)
	return urls
	
def makeLinkFromAnchor(anchor, url):
	try:
		if anchor[0:4] == "http" or anchor[0:4]  == "www":
			return anchor
		if anchor[0] == "/":
			return url+anchor
		else:
			return url+"/"+anchor
	except:
		return url
	
	
def getLinks(page, siteUrl):
	linkpat = re.compile(r'<a\s+(?:[^>]*?\s+)?href="([^"]*)"')
	anchors = re.findall(linkpat, str(page))
	links = []
	extlinks = []
	for anchor in anchors:
		link = makeLinkFromAnchor(anchor, siteUrl)		
		if(urlparse(link).netloc != urlparse(siteUrl).netloc):
			extlinks.append(link)
		else:
			links.append(link)
	return links, extlinks
	
def getEmails(page):
	emailpat = re.compile(r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
	emails = re.findall(emailpat, str(page))
	if emails:
		for email in emails:
			emailsToWrite.put(email)
		return emails

def makeRequest(url):
	try:
		page = urllib.request.urlopen(url).read()
	except:
		return
	
def getDataFromSite(url, siteUrl, level):
	try:
		page = urllib.request.urlopen(url).read()
	except:
		return
	if level == 1:
		urlsToWrite.put(siteUrl)
		print(threading.current_thread().name, siteUrl)
	links, extLinks = getLinks(page, siteUrl)
	
	emails = []
	e1 = getEmails(page)
	if e1:
		emails.append(e1)
	
	if extLinks:
		for extlink in extLinks:
			if(extlink not in visitedExtLinks):
				makeRequest(extlink)
				#print(siteUrl, extlink)
				visitedExtLinks.append(extlink)
	
	if (not emails or not extLinks) and level > 0:
		i=0
		for link in links:
			if i > 20:
				break
			e = getDataFromSite(link, siteUrl, level-1)
			if e:
				emails.append(e)
			if emails:
				break
			i+=1
	return emails

def snifferMain():
	filters = estIps()
	sniff(filters)
	
def bingMails(ip):
	urls = getBingUrlsByIp(ip)
	urls = list(set(urls))
	i = 0
	emails = []
	for url in urls:
		emails.append(getDataFromSite('http://'+url,'http://'+url, 1)) #bingist tuleb ilma http-ta.
	#print("Got "+str(len(emails))+"emails from "+ip)
	#appendToFile([emails], "emails")
	
def crawlEmails():
	while True:
		ip = toCrawlIPs.get()
		try:
			bingMails(ip)
			toCrawlIPs.task_done()
		except:
			toCrawlIPs.put(ip)
			time.sleep(5)
			print("bing request failed, waiting(5)")
		print("Size(toCrawlIPs): "+str(toCrawlIPs.qsize()))

def manageIp(ip):
	str(ip)
	if ip not in processedIps:
		toCrawlIPs.put(ip)
		processedIps.append(ip)
	else:
		return


def ipManager():
	i = 0
	while True:
		ip = unProcessedIPs.get()
		manageIp(ip)
		unProcessedIPs.task_done()

def writer():
	conn = sqlite3.connect('emails.db')
	c = conn.cursor()
	while True:
		try:
			c.execute("INSERT INTO emails VALUES ('"+emailsToWrite.get()+"')")
			emailsToWrite.task_done()
			c.execute("INSERT INTO urls VALUES ('"+urlsToWrite.get()+"')")
			urlsToWrite.task_done()
			conn.commit()
		except:
			a = True

print("hello")

visitedExtLinks = []
processedIps = []
unProcessedIPs = q.Queue()
toCrawlIPs = q.Queue()
emailsToWrite = q.Queue()
urlsToWrite = q.Queue()


sniffer = threading.Thread(target=snifferMain)
sniffer.start()

writer = threading.Thread(target=writer)
writer.start()

manager = threading.Thread(target=ipManager)
manager.start()

for k in range(0, 35):
	k = threading.Thread(target=crawlEmails)
	k.setDaemon(True)
	k.start()

unProcessedIPs.join()
toCrawlIPs.join()