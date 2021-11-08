import argparse
import sys
import requests
import os
from log import *


#--------------------
# Constants
#--------------------

HSTS = 'strict-transport-security'
XFO = 'x-frame-options'
CSP = ''

#--------------------
# Functions
#--------------------

def load_input_file(inputfile):
	"""
	Takes a string representing the name of an existent file and returns a list with each line of the file
	The file must exist in the file system before calling this function. 
	"""
	with open(inputfile, 'r') as f:
		f = f.readlines()
	for i in range(len(f)):
		f[i] = f[i].replace('\n','').replace('\r','')
	return f	


def get_headers(url):
	"""
	Takes a url (string) as argument and performs a GET or HEAD request.
	Returns a dictionary with the response headers.
	"""
	ret = {}
	h = requests.head(url)
	if h.status_code == 405:
		h = requests.get(url)
	raw = dict(h.headers)
	for i in raw.keys():
		ret[i.lower().strip()] = raw[i].lower().strip()
	return ret

 
def is_present(header, headers):
	"""
	Takes a string as the frist argument and a dictionary as the second
	Returns true if the header exists in headers.
	"""
	i = 0
	ret = False
	header = header.lower().strip()
	headers = list(headers.keys())
	while i < len(headers) and ret == False:
		if header == headers[i]:
			ret = True
		i += 1
	return ret	


def get_domain(url):
	"""
	Takes a url as input and returns the domain string.
	"""	
	if 'https' in url:
		proto = 'https'
	elif 'http' in url:
		proto = 'http'
	domain = url.split(proto+'://')[1]
	if '/' in url:
		domain = domain.split('/')[0]
	domain = domain.split('.')
	domain = domain[-2] + '.' + domain[-1]
	return domain 

def check_hsts_header(hsts):
	"""
	Checks if the HSTS header is correctly configured according to RFC and best practices
	"""
	ret = {'includesubdomains':False, 'preload':False, 'max-age':False}
	if 'includesubdomains' in hsts:
		ret['includesubdomains'] = True
	if 'preload' in hsts:
		ret['preload'] = True
	for i in hsts:
		if 'max-age' in i:
			max_age = i.split('=')
	if len(max_age) == 2:
		max_age = max_age[1]
		if int(max_age) > 10368000:
			ret['max-age'] = True
	return ret
			

def check_xfo_header(xfo_header,domain): 
	ret = False
	if xfo_header in ['deny','sameorigin']:
		ret = True
	elif 'allow-from' in xfo_header:
		xfo = xfo_header.split(':').strip()
		if xfo == domain:
			ret = True
	return ret

def check_csp_header(csp_headers):


#def check_server_header(server_header):
	"""
	Takes a dictionary containing the response headers
	Cheks if the server header contains version information
	The Server header must be present in headers
	"""

#def check_xpowered_header():


#--------------------
# Main
#--------------------
def main():
	parser = argparse.ArgumentParser()
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument("target", type=str, help="Target URL string", nargs="*",default="")
	group.add_argument("-i", "--input_file", type=str, help="Input file containing a list of URLs")
	args = parser.parse_args()

	if args.input_file:
		if os.path.exists(args.input_file):
			targets = load_input_file(args.input_file)
		else:
			log_stderr("Targets file does not exist")
	else:
		targets = args.target

	results = {
		'Missing HSTS Header':[],
		'Weak HSTS Configuration':[],
		'Missing XFO Header':[],
		'Weak XFO Configuration':[]
	}
	for target in targets:
		headers = get_headers(target)
		if is_present(HSTS,headers):
			log_stderr("HSTS is present")
			hsts = [ i.strip() for i in headers.get(HSTS).split(';')]	
			hsts_results = check_hsts_header(hsts)
			for i in hsts_results.values():
				if not i:
					results['Weak HSTS Configuration'].append(target)
		else:
			results["Missing HSTS Header"].append(target)
		if is_present(XFO,headers):
			log_stderr("XFO is present")
			xfo = headers[XFO]
			if not check_xfo_header(xfo,get_domain(target)):
				results["Weak XFO Configuration"].append(target)
		else:
			results["Missing XFO Header"].append(target)
	
	for i in results.keys():
		if len(results[i]) > 0:
			log_stdout(i)
			log_stdout("\t"+target)


if __name__ == "__main__":
	main()
