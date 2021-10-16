
import argparse
import requests
import ipaddress
import json
import sys
import os

# -----------------------------------------------
# Constants
# -----------------------------------------------

rdap_url = "https://rdap.arin.net/registry/ip/"

# -----------------------------------------------
# Functions
# -----------------------------------------------

def log_out(message):
	sys.stdout.write("[+] %s\n"  % message)


def log_err(message):
	sys.stderr.write("[-] %s\n" % message)

def is_public_ip(ip):
	try:
		ip = ipaddress.IPv4Address(ip)
		return ip.is_global
	except ValueError as e:
		log_err(e)
		return False
		
def is_public_network(net):
	try:
		net = ipaddress.IPv4Network(net)
		return net.is_global
	except ValueError as e:
		log_err(e)
		return False


def load_targets_file(input_file):
	with open(input_file, 'r') as f:
		f = f.readlines()
	out = [i.replace('\n','').replace('\r','') for i in f]
	return out

def parse_targets(targets):
	out_targets = list()
	for target in targets:
		if "/" in target:
			if is_public_network(target):
				out_targets.append(target)
		else:
			if is_public_ip(target):
				out_targets.append(target)
			
	return out_targets

def query_rdap(target, rdap_url):
	url = rdap_url + target
	r = requests.get(url)
	return r.text


def get_owner(rdap_data):
	data = json.loads(rdap_data)
	return data['entities'][0]['vcardArray'][1][1][-1]

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
			log_err("Targets file does not exist")
	else:
		targets = args.target

	targets = parse_targets(targets)
	for target in targets:
		rdap_data = query_rdap(target, rdap_url)
		message = "Target: %s belongs to: %s" % (target, get_owner(rdap_data))
		log_out(message)
