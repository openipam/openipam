# Functions for validation

import re

# useful regexes
#  * dotted-quad IP
ip = "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?![\\d])"
#  * CIDR mask (0-32)
cidrmask = "([1-2]?[0-9]|3[0-2])"
#  * FQDN
fqdn = "([0-9A-Za-z]+\.[0-9A-Za-z]+|[0-9A-Za-z]+[\-0-9A-Za-z\.]*[0-9A-Za-z])"
#  * hostname
hostname = "([0-9A-Za-z]+|[0-9A-Za-z][\-0-9A-Za-z]*[0-9A-Za-z])"

def is_mac(string):
	'''Returns true if argument is ethernet address, false otherwise'''
	mac = "[0-9a-fA-F][0-9a-fA-F][:\-.]?[0-9a-fA-F][0-9a-fA-F][:\-.]?[0-9a-fA-F][0-9a-fA-F][:\-.]?[0-9a-fA-F][0-9a-fA-F][:\-.]?[0-9a-fA-F][0-9a-fA-F][:\-.]?[0-9a-fA-F][0-9a-fA-F]"
	re_mac = re.compile("^" + mac + "$")
	return re_mac.search(string)


def is_ip(string):
	'''Returns true if argument is an IP address, false otherwise'''
	re_ip = re.compile("^"+ip+"$")
	return re_ip.search(string)


def is_cidr(string):
	'''Returns true if argument is valid classless inter-domain routing syntax, false otherwise'''
	re_cidr = re.compile("^"+ip+"/"+cidrmask+"$")
	return re_cidr.search(string)


def is_fqdn(string):
	'''
	Returns true if argument is syntactically a fully qualified domain name, false otherwise
	Doesn't actually validate TLDs, mostly allows periods past hostnames
	'''
	re_fqdn = re.compile("^"+fqdn+"$")
	return re_fqdn.search(string)


def is_hostname(string):
	'''Returns true if argument is a valid hostname (but not necessarily fully qualified), false otherwise'''
	re_hostname = re.compile("^"+hostname+"$")
	return re_hostname.search(string)


def is_srv_content(string):
	'''
	Validate an srv record's content field
	Assumes priority has already been stripped out
	'''
	
	re_srv = re.compile('^(\d+ \d+ %s)$' % fqdn)
		
	return re_srv.search(string)


def is_soa_content(string):
	'''Validate an soa record's content field'''
	
	re_soa = re.compile('^%s [A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4} \d+ \d+ \d+ \d+ \d+$' % fqdn)
		
	return re_soa.search(string)

