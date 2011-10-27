#!/usr/bin/env python


import dhcp_constants
import dhcp_packet
import dhcp_network

import type_hw_addr
import type_ipv4
import type_strlist

import sys

from optparse import OptionParser


parser = OptionParser()

""" Action options """
parser.add_option("-L", "--listen", action="store_true",dest="listen", help="",default="False")
parser.add_option("-E", "--emit",  action="store_true",dest="emit", help="",  default="False")
parser.add_option("-R", "--readable-conversion",  action="store_true",dest="readable", help="", default="False")
parser.add_option("-B", "--binary-conversion",  action="store_true",dest="binary", help="", default="False")


parser.add_option("-s", "--source-file", action="store",dest="source", help="", default="False", type="string")
parser.add_option("-d", "--destination-file", action="store",dest="destination", help="", default="False", type="string")



(options, args) = parser.parse_args()

print options



def main() :
    ActionSum = 0
    for Action in (options.listen,options.emit,options.readable,options.binary) :
        if Action == True : ActionSum += 1
    if ActionSum > 1 :
        print "Command line error : [-L -E -R -B] Only one of these actions can be taken."
        sys.exit(0)

    if options.readable == True : r_conversion()



def listen(port) :
    pass

def emit(address,port) :
    pass

def r_conversion() :
    rawdata = rawdata = sys.stdin.read()
    while ( len(rawdata)>0 ) :
        readdata = dhcp_packet.DhcpPacket()
        readdata.DecodePacket(rawdata)
        readdata.PrintHeaders()
        readdata.PrintOptions()
        rawdata = rawdata = sys.stdin.read()

def b_conversion() :
    pass

main()
