#!/usr/bin/python -u
# DO NOT remove the '-u' (unbuffered stdin/stdout/stderr).  PowerDNS chokes without it.

"""Script for the PowerDNS pipe backend to respond to all A or ANY queries
with an A record to the specified IP address."""

import sys
import os
import stat

pdns_start_time = os.stat("/var/run/pdns.pid")[stat.ST_MTIME]

nsname = "captive.ipam.usu.edu"
address = "129.123.54.35"

default_ttl = 120

soa_content = f"{nsname} hostmaster@usu.edu {pdns_start_time} {default_ttl} 3600 604800 3600"

debug = 5


def print_error(err_string, min_debug=2):
    if min_debug < debug:
        sys.stderr.write("\t%s" % err_string)
        err_file = open("/tmp/pdns_captive.py.errors", "a")
        err_file.write("\t%s" % err_string)
        err_file.close()


def send(line):
    if line[-1:] != "\n":
        print_error(
            "String did not have required endline as the last character, added.\n"
        )
        line += "\n"
    sys.stdout.write(line)
    print_error("Sending '%s' to PowerDNS\n" % line.strip("\n"), 3)


def read_line():
    line = sys.stdin.readline().strip("\n")
    if line == "":
        # AKA 'EOF'
        print_error("Got EOF, refusing to go on.\n", 1)
        raise Exception("Got EOF, exiting.")
    print_error("got '%s' from PowerDNS\n" % line, 3)
    return line


def data(qname, qclass, qtype, ttl, id, content):
    send(f"DATA\t{qname}\t{qclass}\t{qtype}\t{ttl}\t{id}\t{content}\n")


def end():
    send("END\n")


def fail():
    send("FAIL\n")


def log(str):
    send("LOG %s" % str)


def handle_query(qname, qclass, qtype, id, remote_ip, local_ip):
    """Handle a request from powerdns
    @param qname: name of the record we are looking for
    @param qclass: class (should be 'IN')
    @param qtype: type of record ('A', 'CNAME', 'ANY', 'MX', ...)
    @param id: ID of the domain we are searching in or -1 if not known
    @param remote_ip: ip address of the nameserver/client requesting this data from
    PowerDNS
    @param local_ip: ip address of PowerDNS that the query was sent to"""
    # qname_lvl = len(qname.split("."))
    if qtype == "PTR" or qtype == "ANY":
        data(qname, qclass, "PTR", -1, 1, nsname)
    elif qtype == "A" or qtype == "ANY":
        # unconditionally return an A record with the given address in domain id 1
        if len(qname.split(".")) == 1 and qtype == "ANY":
            data(qname, qclass, "SOA", default_ttl, 1, soa_content)
            data(qname, qclass, "NS", -1, 1, nsname)
        elif qname == "bluezone-dev.usu.edu":
            data(qname, qclass, "A", -1, 1, "129.123.54.16")
        else:
            data(qname, qclass, "A", -1, 1, address)
            # FIXME: if the backend gets just an 'END', it will assume there were no
            # matching records
    end()


def handle_axfr(id):
    if False and id == 1:
        data("", qclass, "SOA", default_ttl, 1, soa_content)
        data("", qclass, "NS", -1, 1, nsname)
        data(nsname, qclass, "A", -1, 1, address)
    end()


if __name__ == "__main__":
    # First, we should get a HELO from powerdns
    print_error("start time: %s\n" % pdns_start_time, 5)

    line = read_line()
    fields = line.split("\t")
    if fields[0] != "HELO":
        raise Exception("Server did not send HELO.")
    abi = int(fields[1])
    if abi != 1 and abi != 2:
        raise Exception("Unrecognized ABI: %s" % abi)
    send('OK\t"That A record points to me" backend started\n')
    while True:
        line = read_line()
        # queries come in a tab-separated list
        fields = line.split("\t")
        if abi == 2 and len(fields) == 7 and fields[0] == "Q":
            # ABI version 2
            type, qname, qclass, qtype, id, remote_address, local_address = fields
        elif abi == 1 and len(fields) == 6 and fields[0] == "Q":
            # ABI version 1
            type, qname, qclass, qtype, id, remote_address = fields
            local_address = None
        elif fields[0] == "AXFR":
            domain = fields[1]
            # We don't really support AXFR, we just give an NS, SOA, and A record back
            handle_axfr(domain)
        elif fields[0] == "PING":
            # Not sure what is expected from a PING
            end()
        else:
            print_error(
                "Got unrecognized input from PowerDNS (wrong number of fields): '%s'\n"
                % line,
                2,
            )
            fail()
            continue
        handle_query(qname, qclass, qtype, id, remote_address, local_address)
