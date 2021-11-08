
import argparse
import requests
import ipaddress
import sys
import os
from log import *

# -----------------------------------------------
# Constants
# -----------------------------------------------

RDAP_BASE_URL = "https://rdap.arin.net/registry"

# -----------------------------------------------
# Functions
# -----------------------------------------------


def is_public(target):
	"""
	Takes a string and returns True if is a public IP address or network in CIDR notation
	"""
	ret = False
	if "/" in target:
		try:
			net = ipaddress.IPv4Network(target)
			ret =  net.is_global
		except ValueError as e:
			log_stderr(e)
	else:
		try:
			ip = ipaddress.IPv4Address(target)
			ret =  ip.is_global
		except ValueError as e:
			log_stderr(e)
	return ret
		

def load_targets_file(input_file):
	"""
	Takes a string indicating a file name and reads the contents of the file.
	Returns a list containing each line of the file.
	Precondition: input_file should exist in the file system.
	"""
	with open(input_file, 'r') as f:
		f = f.readlines()
	out = [i.replace('\n','').replace('\r','') for i in f]
	return out

def parse_targets(targets):
	"""
	Takes a list containing strings and returns another list i
	containing the values from the input list that matched a public IP address or network.
	"""
	out_targets = list()
	for target in targets:
		if is_public(target):
			out_targets.append(target)
			
	return out_targets

def query_rdap(target):
	"""
	Queries Whois information from the RDAP_BASE_URL and returns a JSON object
	"""
	url = RDAP_BASE_URL +"/ip/"+ target
	r = requests.get(url)
	return r.json()


def get_owner(rdap_data):
	return rdap_data['entities'][0]['vcardArray'][1][1][-1]


# -----------------------------------------------
# Main
# -----------------------------------------------

if __name__ == "__main__":

	parser = argparse.ArgumentParser()
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument("target", type=str, help="Target IP address or subnetworks (CIDR) separated by a space", nargs="*",default="")
	group.add_argument("-i", "--input_file", type=str, help="Input file containing a list of IP addresses or subnetworks (CIDR). The file must contain one IP address or subnet on each line")
	args = parser.parse_args()

	if args.input_file:
		if os.path.exists(args.input_file):
			targets = load_targets_file(args.input_file)
		else:
			log_stderr("Targets file does not exist")
	else:
		targets = args.target

	targets = parse_targets(targets)
	for target in targets:
		rdap_data = query_rdap(target)
		message = "Target: %s is registered under %s" % (target, get_owner(rdap_data))
		log_stdout(message)
