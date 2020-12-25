#!/usr/bin/python3
# Copyright 2019, Aniket.N.Bhagwate, All rights reserved.
# Date Created : 22 June 2019
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


import os
import time 
import threading
from colorama import Fore, Back, Style
os.system("clear")
print(Fore.GREEN + Style.BRIGHT + "")
banner = """
	|------------------------------------------------|
	|   /\/|___  _____ ____ _  _____  _   _ /\/| 	 |
	|  |/\/  _ \| ____/ ___| |/ / _ \| \ | |/\/  	 |
	|     | |_) |  _|| |   | ' / | | |  \| |     	 |
	|     |  _ <| |__| |___| . \ |_| | |\  |     	 |
	|     |_| \_\_____\____|_|\_\___/|_| \_|     	 |
	|------------------------------------------------|
	|-> -> -> -> -> -> -> -> THE ULTIMATE RECON TOOL | 
	|------------------------------------------------|
	|################################################|
	|#[!] THIS TOOL WILL FIND THE FOLLOWING INFO :###|
	|################################################| 
	| """+Fore.CYAN + Style.BRIGHT +"""[#] SUBDOMAINS"""+Fore.GREEN + Style.BRIGHT +""" 				 |
	| """+Fore.CYAN + Style.BRIGHT +"""[#] HIDDEN DIRECTORIES"""+Fore.GREEN + Style.BRIGHT +"""			 |
	| """+Fore.CYAN + Style.BRIGHT +"""[#] SCAN REPORTS --> (NMAP)"""+Fore.GREEN + Style.BRIGHT +"""			 |
	| """+Fore.CYAN + Style.BRIGHT +"""[#] WEB (SSL/TLS) VULNERABILITIES"""+Fore.GREEN + Style.BRIGHT +"""		 |
	| """+Fore.CYAN + Style.BRIGHT +"""[#] INTERNAL_FILES, ROBOTS"""+Fore.GREEN + Style.BRIGHT +"""			 |
	| """+Fore.CYAN + Style.BRIGHT +"""[#] POTENTIAL GENERIC VULNERABILITIES"""+Fore.GREEN + Style.BRIGHT +"""		 |
	| """+Fore.CYAN + Style.BRIGHT +"""[#] CORS"""+Fore.GREEN + Style.BRIGHT +"""					 |
	|################################################| 
		 __  	          __ 
		| _|             |_ |
		| |   	          | |
		| | ENTER THE URL | |
		| |   	          | |
		|__|             |__|
		
		[#] Eg: """+Fore.CYAN + Style.BRIGHT +"""www.cisco.com"""+Fore.GREEN + Style.BRIGHT +"""
"""
###############################################################################
print(banner)

url = input("Enter URL : "+Fore.CYAN + Style.BRIGHT)
org_url=url
newurl=''
url = url.split(".")
if url[0]=='www':
	url.remove('www')
	for x in url:
		newurl+=x+"."
		url = newurl[:-1]
else:
	for x in url:
		newurl+=x+"."
		url = newurl[:-1]


start_time = time.time()
localtime = time.asctime( time.localtime(time.time()) )
lt = str(localtime).replace(" ","_")
os.system("mkdir DUMP")
os.system("mkdir _SCANS_ 2> DUMP/error.txt")		# here 2> is used becoz if the dir already exists , it will throw error
os.system("mkdir _SCANS_/{}{}".format(org_url,lt))	# so just transfer all the std error to error.txt
os.system("chmod +x _source_/testssl/testssl.sh")
os.system("mkdir _SCANS_/{}{}/NMAP_DNS_MAIL".format(org_url,lt))
###################################################################################
print(banner)

clear = lambda:os.system("clear")		# Function for clearing screen


print(Fore.GREEN + Style.BRIGHT +" ")
clear()
print(banner)
print("-----------------------------------------------")
print("STARTED ANALYSIS ON --> "+Fore.CYAN + Style.BRIGHT+"[  {}  ]".format(url))
print(Fore.GREEN + Style.BRIGHT+"-----------------------------------------------")

###############################
# FUNCTIONS
##############################

def ct():# requires www stripped off
	os.system("python3 _source_/ct/ct-exposer.py -d {}  1> _SCANS_/{}{}/SUBDOMAINS_ 2> DUMP/error.txt".format(url,org_url,lt))
	f = open("_SCANS_/{}{}/SUBDOMAINS_".format(org_url,lt),"r")
	f = f.read()
	f = f.split("\n")
	f.remove(f[0])
	f.remove(f[0])
	f.remove(f[0])
	f.remove(f[0])
	f.remove(f[0])
	target = f.index('')
	f = f[:target+1]
	f.pop()
	open("_SCANS_/{}{}/SUBDOMAINS_".format(org_url,lt),"w").close()
	k = open("_SCANS_/{}{}/SUBDOMAINS_".format(org_url,lt),"a")
	for x in f:
		x = x.split("\t")
		k.write(x[0]+" "+x[1])
		k.write("\n")
	k.close()
	print(Fore.CYAN + Style.BRIGHT+"------------------------> [!]SUBDOMAINS-[COMPLETED]"+Fore.GREEN + Style.BRIGHT)	


def photon():		# FOR FINDING INTERNAL FILES ,ROBOTS ETC	# requires original
	os.system("python3 _source_/photon/photon.py -u {} 1> DUMP/error.txt 2> DUMP/error.txt".format(org_url))
	os.system("mv {} _SCANS_/{}{}/PHOTON_OBTAINED_DATA/".format(org_url,org_url,lt))
	print(Fore.CYAN + Style.BRIGHT+"------------------------> [!]INTERNAL FILES-[COMPLETED]"+Fore.GREEN + Style.BRIGHT)

def testssl():		# FOR FINDING SSL/TLS VULNERABILITIES	# requires original
	os.system("./_source_/testssl/testssl.sh {}  1> _SCANS_/{}{}/SSL_TLS_VULNERABILITIES 2> DUMP/error.txt".format(org_url,org_url,lt))
	print(Fore.CYAN + Style.BRIGHT+"------------------------> [!]SSL/TLS VULNERABILITIES-[COMPLETED]"+Fore.GREEN + Style.BRIGHT)


def dirb():		# FOR FINDING HIDDEN DIRECTORIES	# requires original
	os.system("dirb https://{} /usr/share/dirb/wordlists/small.txt 1> _SCANS_/{}{}/HIDDEN_DIRECTORIES 2> DUMP/error.txt".format(org_url,org_url,lt))
	f = open("_SCANS_/{}{}/HIDDEN_DIRECTORIES".format(org_url,lt),"r")
	f = f.read().split("\n")
	f.pop()
	try:
		for x in f:
			f.remove('                                                                                                                                                     ')
	except:
		pass
	f.pop()
	for x in range(0,19):
		f.remove(f[0])
	open("_SCANS_/{}{}/HIDDEN_DIRECTORIES".format(org_url,lt),"w").close()
	k = open("_SCANS_/{}{}/HIDDEN_DIRECTORIES".format(org_url,lt),"a")
	for x in f:
		if list(x)[0]=='+':
			k.write(x+"\n")
	k.close()
	f = open("_SCANS_/{}{}/HIDDEN_DIRECTORIES".format(org_url,lt),"r")
	f = f.read().split("\n")
	open("_SCANS_/{}{}/HIDDEN_DIRECTORIES".format(org_url,lt),"w").close()
	p = open("_SCANS_/{}{}/HIDDEN_DIRECTORIES".format(org_url,lt),"a")
	try:
		for x in f:
			v = x.split("(")
			v = v[1].split("|")
			k1=v[0].split(":")
			k2=v[1].split(":")
			z = k2[1].split(")")
			if k1[1]<'400' and z[0]>'0':
				p.write(x+"\n")
		p.write()
		print(Fore.CYAN + Style.BRIGHT+"------------------------> [!]HIDDEN DIRECTORIES-[COMPLETED]"+Fore.GREEN + Style.BRIGHT)

	except:
		pass


def mail_dns():	# requries www stripped off
	os.system("dnsenum {} 1> _SCANS_/{}{}/MAIL_DNS_INFO 2> DUMP/error.txt".format(url,org_url,lt))
	print(Fore.CYAN + Style.BRIGHT+"------------------------> [!]MAIL AND DNS SERVERS-[COMPLETED]"+Fore.GREEN + Style.BRIGHT)

def nmap_domain():	# requires both
	os.system("nmap -sV {} 1>> _SCANS_/{}{}/NMAP_DOMAIN_REPORT.txt 2> DUMP/error.txt".format(org_url,org_url,lt))
	os.system("nmap -sV {} 1>> _SCANS_/{}{}/NMAP_DOMAIN_REPORT.txt 2> DUMP/error.txt".format(url,org_url,lt))
	print(Fore.CYAN + Style.BRIGHT+"------------------------> [!]NMAP(MAIN DOMAIN)-[COMPLETED]"+Fore.GREEN + Style.BRIGHT)
	
def nmap_dns_mail():	# requires www stripped off
	import os 
	os.system("host -t mx {} | cut -d' ' -f7 1> DUMP/mail.txt 2> DUMP/error.txt".format(url))
	f = open("DUMP/mail.txt","r")
	f = f.read().split("\n")
	f.pop()
	open("DUMP/mail.txt","w").close()
	for x in f:
		os.system("host {} | grep 'has address' | cut -d ' ' -f4 1>> DUMP/mail.txt 2> DUMP/error.txt".format(x))
	os.system("host -t ns {} | cut -d' ' -f4 1> DUMP/dns.txt 2> DUMP/error.txt".format(url))
	f = open("DUMP/dns.txt","r")
	f = f.read().split("\n")
	f.pop()
	for x in f:
		os.system("host {} | grep 'has address' | cut -d ' ' -f4 1>> DUMP/mail.txt 2> DUMP/error.txt".format(x))
	f = open("DUMP/mail.txt","r")
	f = f.read().split("\n")
	f.pop()
	for x in f:
		os.system("nmap -sV {} 1> _SCANS_/{}{}/NMAP_DNS_MAIL/{}.txt 2> DUMP/error.txt".format(x,org_url,lt,x))
	print(Fore.CYAN + Style.BRIGHT+"------------------------> [!]NMAP(MAIL AND DNS SERVERS)-[COMPLETED]"+Fore.GREEN + Style.BRIGHT)

def cors():
	os.system("curl https://{} -H".format(url) + ' "Origin: {}" '.format("http://bing.com") + "-I 1> _SCANS_/{}{}/CURL 2> DUMP/error.txt".format(org_url,lt))
	print(Fore.CYAN + Style.BRIGHT+"------------------------> [!]CORS VULNERABILITIES-[COMPLETED]"+Fore.GREEN + Style.BRIGHT)


#-----------------------------------MULTI-Threading STUFF -----------------------------------------------------
t1 = threading.Thread(target=ct)		
t2 = threading.Thread(target=photon)
t3 = threading.Thread(target=testssl)
t4 = threading.Thread(target=dirb)
t6 = threading.Thread(target=mail_dns)
t7 = threading.Thread(target=nmap_domain)
t8 = threading.Thread(target=nmap_dns_mail)
t9 = threading.Thread(target=cors)

# STARTING THREADS
t1.start()
t2.start() 
t3.start()  
t4.start() 
t6.start()
t7.start()
t8.start()
t9.start()
	
# PAUSE MAIN PROCESS TILL ALL THREADS HAVE COMPLETED EXECUTION !
t1.join()
t2.join()
t3.join()
t4.join()
t6.join()
t7.join()
t8.join()
t9.join()
#------------------------------------------------------------------------------------------------------------

tim = time.time()-start_time
tim = str(tim).split(".")
tim = round(int(tim[0])/60)
os.system("rm -rf DUMP")

clear()
print(banner)
print(Fore.CYAN + Style.BRIGHT+"[!] SCAN COMPLETED !!"+Fore.GREEN + Style.BRIGHT)
input(Fore.RED + Style.BRIGHT+"[!] PRESS ENTER TO CONTINUE !!\n"+Fore.GREEN + Style.BRIGHT)

print("[->] [SUBDOMAINS]			--> SAVED IN -->"+Fore.CYAN + Style.BRIGHT+"SUBDOMAINS_"+Fore.GREEN + Style.BRIGHT)
print("[->] [INTERNAL FILES]			--> SAVED IN -->"+Fore.CYAN + Style.BRIGHT+"PHOTON_OBTAINED_DATA/"+Fore.GREEN + Style.BRIGHT)
print("[->] [SSL/TLS VULNERABILITIES]		--> SAVED IN -->"+Fore.CYAN + Style.BRIGHT+"SSL_TLS_VULNERABILITIES"+Fore.GREEN + Style.BRIGHT)
print("[->] [HIDDEN DIRECTORIES]		--> SAVED IN -->"+Fore.CYAN + Style.BRIGHT+"HIDDEN_DIRECTORIES"+Fore.GREEN + Style.BRIGHT)
print("[->] [MAIL AND DNS]			--> SAVED IN -->"+Fore.CYAN + Style.BRIGHT+"MAIL_DNS_INFO"+Fore.GREEN + Style.BRIGHT)
print("[->] [NMAP(MAIN DOMAIN)]			--> SAVED IN -->"+Fore.CYAN + Style.BRIGHT+"NMAP_DOMAIN_REPORT.txt"+Fore.GREEN + Style.BRIGHT)
print("[->] [NMAP(MAIL AND DNS SERVERS)]	--> SAVED IN -->"+Fore.CYAN + Style.BRIGHT+"NMAP_DNS_MAIL/<ip>"+Fore.GREEN + Style.BRIGHT)
print("[->] [CORS VULNERABILITIES]		--> SAVED IN -->"+Fore.CYAN + Style.BRIGHT+"CORS"+Fore.GREEN + Style.BRIGHT)

print("TIME TAKEN FOR ANALYSIS : [ {} ] (MINUTES)".format(tim))



'''
update can be added for empty files :

if os.stat("empty.txt").st_size==0:
	print("the file is empty")
'''


