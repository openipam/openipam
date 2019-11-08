# Functions for validation that shouldn't even exist.

import openipam.iptypes
import re

# useful regexes
#  * MAC address
mac = r"[0-9a-fA-F][0-9a-fA-F][:\-.]?"
#  * FQDN
fqdn = r"([0-9A-Za-z]+\.[0-9A-Za-z]+|[0-9A-Za-z]+[\-0-9A-Za-z\.]*[0-9A-Za-z])"
#  * hostname
hostname = r"([0-9A-Za-z]+|[0-9A-Za-z][\-0-9A-Za-z]*[0-9A-Za-z])"


def is_mac(string):
    """Returns true if argument is ethernet address, false otherwise"""
    re_mac = re.compile("^" + mac + "$")
    return re_mac.search(string)


def is_ip(string):
    """Returns true if argument is an IP address, false otherwise"""
    try:
        if is_mac(string):
            return False
        ip = openipam.iptypes.IP(string)
        if len(ip) == 1:
            return True
    except Exception:
        pass
    return False


def is_cidr(string):
    """Returns true if argument is valid CIDR syntax, false otherwise"""
    try:
        x = openipam.iptypes.IP(string)
        if x.len() > 1:
            return True
    except Exception:
        pass
    return False


def is_fqdn(string):
    """
    Returns true if argument is a valid fully qualified domain name, false otherwise
    Doesn't actually validate TLDs, mostly allows periods past hostnames
    """
    re_fqdn = re.compile("^" + fqdn + "$")
    return re_fqdn.search(string)


def is_hostname(string):
    """Returns true if argument is a valid hostname, false otherwise"""
    re_hostname = re.compile("^" + hostname + "$")
    return re_hostname.search(string)


def is_srv_content(string):
    """
    Validate an srv record's content field
    Assumes priority has already been stripped out
    """

    re_srv = re.compile(r"^(\d+ \d+ %s)$" % fqdn)

    return re_srv.search(string)


def is_soa_content(string):
    """Validate an soa record's content field"""

    re_soa = re.compile(
        r"^%s [A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4} \d+ \d+ \d+ \d+ \d+$" % fqdn
    )

    return re_soa.search(string)
