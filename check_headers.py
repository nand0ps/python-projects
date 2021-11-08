import argparse
import sys
import requests
import os
import re
from socket import gethostbyname
from log import *


#--------------------
# Constants
#--------------------

HEADERS = {
	'HSTS':'strict-transport-security',
	'XFO':'x-frame-options',
	'CSP':'content-security-policy'}
SERVER = 'server'
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


def get_fqdn(url):
	"""
	Takes a url as input and returns the fqdn string.
	"""	
	if 'https' in url:
		proto = 'https'
	elif 'http' in url:
		proto = 'http'
	fqdn = url.split(proto+'://')[1]
	if '/' in url:
		fqdn = fqdn.split('/')[0]
	return fqdn


def check_server_header(server):
	"""
	Takes a dictionary containing the response headers
	Cheks if the server header contains version information
	The Server header must be present in headers
	"""
	return bool(re.search(r'\d',server))
	


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
		'Missing XFO Header':[],
		'Missing CSP Header':[],
		'Server Header with version Information':[]
	}
	for target in targets:
		headers = get_headers(target)
		host = get_fqdn(target)
		ip = gethostbyname(host)
		host_info = ' | '.join([ip,host,target])
		for header in HEADERS.keys():
			if not is_present(HEADERS[header],headers):
				results['Missing '+header+' Header'].append(host_info)
			if is_present(SERVER,headers):
				server = headers.get(SERVER).strip()
		if check_server_header(server):
			results['Server Header with version Information'].append(host_info+' '+server)
	
	for i in results.keys():
		if len(results[i]) > 0:
			log_stdout(i)
			for entry in results[i]:
				log_stdout("---> "+entry)


if __name__ == "__main__":
	main()
