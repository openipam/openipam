#!/usr/bin/env python
#
# pydhcplib
# Copyright (C) 2005 Mathieu Ignacio -- mignacio@april.org
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA

import sys
import os

from pydhcplib.dhcp_constants import DhcpOptions

# FIXME: don't 'import *'
from pydhcplib.dhcp_packet import *
from pydhcplib.dhcp_network import *

#from pydhcplib.dhcp_packet import DhcpPacket
#import dhcp_packet
#import dhcp_network
#from pydhcplib.type_strlist import strlist
#from pydhcplib.type_ipv4 import ipv4

import datetime

#from pydhcplib.dhcp_backend import *
#from event_logger import Log

#from openipam.backend.db import interface
from openipam.utilities import error
from openipam.config import dhcp

import subprocess

from Queue import Full, Empty

DhcpRevOptions = {}
for key in DhcpOptions.keys():
	DhcpRevOptions[ DhcpOptions[key] ] = key

####
show_packets = False

####

def decode_mac( mac ):
	new_mac = []
	for i in mac[:6]: # FIXME: do we care about anything besides ethernet?
		next = "%.2x" % i
		new_mac.append( next )
	return ':'.join(new_mac)

def int_to_4_bytes( num ):
	x = []
	for i in range(4):
		x.insert(0, int( ( int(num) >> (8*int(i)) ) & 0xFF ) )
	return x

def ip_to_list( address ):
	return map( int, address.split('.') )

def bytes_to_ints( bytes ):
	return map(ord, bytes)

def bytes_to_int( bytes ):
	x = 0
	for i in bytes:
		x = (x << 8) | i
	return x

class Server(DhcpServer):
	def __init__(self, dbq):
		DhcpServer.__init__(self,dhcp.listen_address,
					dhcp.client_port,
					dhcp.server_port)
		self.__dbq = dbq
		self.last_seen = {}
	
	def SendPacket(self, packet, dest = None, bootp = False):
		"""Encode and send the packet."""

		giaddr = '.'.join(map(str,packet.GetOption('giaddr')))
		ciaddr = '.'.join(map(str,packet.GetOption('ciaddr')))

		# ALWAYS set these
		# Server-related options:
		packet.SetOption("siaddr",dhcp.server_ip_lst)
		if not bootp:
			packet.SetOption("server_identifier",dhcp.server_ip_lst) # DHCP server IP

		broadcast = packet.GetOption('flags')[0] >> 7

		# FIXME: If !ciaddr and first bit of flags (broadcast bit) is set, broadcast/send to giaddr, otherwise unicast to yiaddr ???

		if not dest:
			dest = ciaddr
		
		if dest != '0.0.0.0':
			#print 'Sending packet directly to %s' % dest
			log_packet(packet, prefix='SND/DIR:')
			self.SendDhcpPacketTo(dest, packet, port=dhcp.client_port)
		elif giaddr!='0.0.0.0':
			#print " - in SendPacket, giaddr != 0.0.0.0, sending to giaddr=%s" % giaddr
			log_packet(packet, prefix='SND/GW:')
			self.SendDhcpPacketTo(giaddr, packet, port=dhcp.server_port)

		# FIXME: This shouldn't broadcast if it has an IP address to send
		# it to instead. See RFC2131 part 4.1 for full details
		else:
			# actually, let's just not do this for now
			#self.SendDhcpPacketTo("255.255.255.255",packet)
			#self.SendDhcpPacketTo(offered_addr,packet, port=68)
			raise Exception("Got a packet without gateway or client address.  Probably local traffic.")

		if show_packets:
			print "------- Sending Packet ----------"
			packet.PrintHeaders()
			packet.PrintOptions()
			print "---------------------------------"
	
	def QueuePacket( self, packet, type ):
		mac = decode_mac( packet.GetOption('chaddr') )
		c_time=datetime.datetime.now()

		# Minimum time between allowing a user to make the same kind of request
		#BETWEEN_REQUESTS = datetime.timedelta(days=0,minutes=0,seconds=10)

		our_key = (mac, type,)

		if self.last_seen.has_key( our_key ):
			time = self.last_seen[ our_key ]
			if ( ( c_time - time ) < dhcp.between_requests ):
				print "ignoring request type %s from mac %s because we saw a request at %s (current: %s)" % (type, mac, str(time), str(c_time))
				log_packet( packet, prefix='IGN/TIME:' )
				return
			else:
				del self.last_seen[ our_key ]
		
		try:
			log_packet( packet, prefix='QUEUED:' )
			self.__dbq.put_nowait( (type, packet) )
		except Full, e:
			# The queue is full, try again later.
			log_packet( packet, prefix='IGN/FULL:' )
			print "ignoring request type %s from mac %s because the queue is full ... be afraid" % (type,mac)
			return
		
		# If we get here, the packet should be in the queue, so we can
		# guarantee it will be seen by one of the workers.  Let's add
		# this to our list of things we don't want to respond to right
		# now.
		self.last_seen[ our_key ] = ( c_time )


	def HandleDhcpDiscover(self, packet):
		self.QueuePacket( packet, 1 )

	def HandleDhcpRequest(self, packet):
		self.QueuePacket( packet, 3 )

	def HandleDhcpDecline(self, packet):
		self.QueuePacket( packet, 4 )
	
	def HandleDhcpRelease(self, packet):
		# update leases set expires = now() where mac=%(mac)s
		self.QueuePacket( packet, 7 )
	
	def HandleDhcpInform(self, packet):
		# see request
		self.QueuePacket( packet, 8 )
	
	def HandleDhcpUnknown(self, packet):
		'''They should have called this 'HandleBootpRequest'''
		# Due to the nature of BOOTP, this should only allow
		# static assignments.
		self.QueuePacket( packet, None )

def parse_packet( packet ):
	type = packet.GetOption('dhcp_message_type')
	mac = decode_mac( packet.GetOption('chaddr') )
	xid = bytes_to_int( packet.GetOption('xid') )
	requested_options = packet.GetOption('parameter_request_list')

	if type in [1,3,4,7,8,]:
		client_ip = '.'.join(map(str,packet.GetOption('ciaddr')))
		if client_ip == '0.0.0.0':
			x = packet.GetOption('request_ip_address')
			if x:
				client_ip = '.'.join(map(str,x))
	else:
		client_ip = '.'.join(map(str,packet.GetOption('yiaddr')))
	
	return (type, mac, xid, client_ip, requested_options)

types = { None:'bootp', 1:'discover', 2:'offer', 3:'request', 4:'decline', 5:'ack', 6:'nak', 7:'release', 8:'inform', }

def log_packet( packet, prefix=''):
	# This should be called for every incoming or outgoing packet.
	type,mac,xid,client,req_opts = parse_packet(packet)
	type = bytes_to_int(type)
	if not type:
		t_name='bootp'
	else:
		t_name = types[type]
	dhcp.get_logger().info("%-10s %-8s %s 0x%08x (%s)", prefix, t_name, mac, xid, client)

def db_consumer( dbq, send_packet ):
	logger = dhcp.get_logger()
	class dhcp_packet_handler:
		# Order matters here.  We want type_map[1] == discover, etc
		def __init__( self, send_packet ):
			from openipam.backend.db import interface
			self.__db = interface.DBDHCPInterface()
			self.SendPacket = send_packet
			# Map our functions to DHCP types
			self.type_map = [
					None, 
					self.dhcp_discover,
					None,
					self.dhcp_request,
					self.dhcp_decline,
					None,
					None,
					self.dhcp_release,
					self.dhcp_inform,
				]
		def handle_packet(self, packet, type):

			if type == None:
				tname, action = ( 'bootp', self.bootp_request )
			else:
				tname = types[type]
				action = self.type_map[ type ]

			if show_packets:
				print "############################# Recieved DHCP %s" % tname
				packet.PrintHeaders()
				packet.PrintOptions()
				print "#############################"

			if action:
				action( packet )
			else:
				print "Don't know how to handle %s packet" % tname

		def address_in_use(self, address):
			if True:
				return False
			if len( map( int, address.split('.') ) ) != 4:
					raise Exception( "'%s' is not a valid IP address" ) % address
			cmd = [ '/bin/ping', '-q', '-i0.1', '-c2', '-W1',  address, ]
			retval = subprocess.call( cmd )
			return not retval

		def bootp_request(self, packet):
			mac = decode_mac( packet.GetOption('chaddr') )
			router = '.'.join(map(str,packet.GetOption('giaddr')))
			ciaddr = '.'.join(map(str,packet.GetOption('ciaddr')))
			opcode = packet.GetOption('op')[0]

			if router == '0.0.0.0':
				log_packet(packet, prefix='IGN/BOOTP:')
				return

			#self.__db.get_static( mac, gateway )
			return
			
		def dhcp_decline(self, packet):
			mac = decode_mac( packet.GetOption('chaddr') )
			requested_ip = '.'.join(map(str,packet.GetOption('request_ip_address')))
			if requested_ip != '0.0.0.0':
				self.__db.mark_abandoned_lease( mac=mac, address=requested_ip )
			else:
				self.__db.mark_abandoned_lease( mac=mac )

		def dhcp_release(self, packet):
			mac = decode_mac( packet.GetOption('chaddr') )
			log_packet( packet, prefix='IGN/REL:' )

		def dhcp_inform(self, packet):
			mac = decode_mac( packet.GetOption('chaddr') )
			client_ip = '.'.join(map(str,packet.GetOption('ciaddr')))
			requested_options = packet.GetOption('parameter_request_list')

			opt_vals = self.__db.retrieve_dhcp_options( mac=mac, address=client_ip, option_ids = requested_options )

			ack = DhcpPacket()
			ack.CreateDhcpAckPacketFrom(packet)

			# FIXME: check the RFC on 'hops'
			hops = packet.GetOption('hops')
			if hops:
				ack.SetOption('hops',hops)

			for opt in opt_vals:
				ack.SetOption( DhcpRevOptions[opt['oid']], bytes_to_ints( opt['value'] ) )
				#print "Setting %s to '%s'" % ( DhcpRevOptions[opt['oid']], bytes_to_ints( opt['value'] ) )

			# send an ack
			self.SendPacket( ack )
		
		def dhcp_discover(self, packet):
			router = '.'.join(map(str,packet.GetOption('giaddr')))
			mac = decode_mac( packet.GetOption('chaddr') )
			requested_ip = '.'.join(map(str,packet.GetOption('request_ip_address')))
			
			if router == '0.0.0.0':
				logger.log( "Ignoring local DHCP traffic from %s (xid:0x%x)", mac, xid )
				return

			if not requested_ip:
				requested_ip = '.'.join(map(str,packet.GetOption('ciaddr')))
				if not requested_ip:
					raise Exception("This really needs fixed...")

			lease = self.__db.make_dhcp_lease(mac, router, requested_ip, discover=True)
			
			print 'Got lease %s from database' % lease

			while self.address_in_use( lease['address'] ):
				print 'Address %s in use, marking lease %s as abandoned' % ( lease['address'], lease )
				self.__db.mark_abandoned_lease( address=lease['address'] )
				lease = self.__db.make_dhcp_lease(mac, router, requested_ip, discover=True)
				print 'Got new lease %s from database' % lease

			# create an offer
			print "> creating offer"
			offer = DhcpPacket()
			offer.CreateDhcpOfferPacketFrom(packet)
			hops = packet.GetOption('hops')
			if hops:
				offer.SetOption('hops',hops)

			# fields
			# FIXME: get a free lease from the DB
			# we will need the function to return: the address, the gateway, the network/netmask/broadcast
			# FIXME: what about lease/renewal/rebinding_time, etc?
			# then offer it

			# Options to request from the DB (address/gateway are assumed)
			offer.SetOption("yiaddr",ip_to_list(lease['address']))

			# options from DB
			print "setting lease time to %s seconds" % lease['lease_time']
			offer.SetOption("ip_address_lease_time",int_to_4_bytes(lease['lease_time'])) # TEST
			#offer.SetOption("renewal_time_value",[0,0,0,60]) # TEST
			#offer.SetOption("rebinding_time_value",[0,0,0,105]) # TEST
			offer.SetOption("subnet_mask",ip_to_list(lease['netmask']))
			offer.SetOption("broadcast_address",ip_to_list(lease['broadcast'])) # TEST
			offer.SetOption("router",ip_to_list(lease['router']))

			#offer.SetOption("hops",[1,]) # TEST: number of hops

			# make a list of requested DHCP options
			requested_options = packet.GetOption('parameter_request_list')
			print "requested_options: %s" % requested_options

			if lease['hostname'] and DhcpOptions['host_name'] in requested_options:
				offer.SetOption("host_name", map(ord,lease['hostname']))

			if requested_options:
				# get option/value pairs from database
				opt_vals = self.__db.retrieve_dhcp_options( mac=mac, address=requested_ip, option_ids = requested_options )
				print "opt_vals: %s" % str(opt_vals)

				for opt in opt_vals:
					offer.SetOption( DhcpRevOptions[opt['oid']], bytes_to_ints( opt['value'] ) )
					print "Setting %s to '%s'" % ( DhcpRevOptions[opt['oid']], bytes_to_ints( opt['value'] ) )

			# send an offer
			print "  > sending offer"
			self.SendPacket(offer)

			#def SendDhcpPacketTo(self, To, packet):
			#	return self.dhcp_socket.sendto(packet.EncodePacket(),(To,self.emit_port))

		def dhcp_request(self, packet):
			# check to see if lease is still valid, if so: extend the lease and send an ACK
			router = '.'.join(map(str,packet.GetOption('giaddr')))
			mac = decode_mac( packet.GetOption('chaddr') )
			ciaddr = '.'.join(map(str,packet.GetOption('ciaddr')))

			# FIXME: If ciaddr is set, we should use a unicast message to the client

			requested_ip = '.'.join(map(str,packet.GetOption('request_ip_address')))
			if not requested_ip:
				requested_ip = ciaddr
				if not requested_ip:
					raise Exception("This really needs fixed...")

			if router == '0.0.0.0':
				# This is traffic directly to our server -- quite possibly a windows client
				router = requested_ip # we only use the router to find the network this device belongs to, so ciaddr should work as well

			giaddr = '.'.join(map(str, packet.GetOption('giaddr')))

			print "mac: %s, requested address: %s" % (mac, requested_ip)
			# make sure a valid lease exists

			lease = self.__db.make_dhcp_lease(mac, router, requested_ip, discover=False)
			print "got lease: %s" % str(lease)
			if lease['address'] != requested_ip:
				# FIXME: Send a DHCP NAK if authoritative
				print "Lease appears invalid... client wants %s, but db gave us %s -- sending NAK" % (requested_ip,lease['address'])
				nak = DhcpPacket()
				# Why use 'NAK' when we can say 'NACK' (which means nothing to me)
				nak.CreateDhcpNackPacketFrom(packet)
				hops = packet.GetOption('hops')
				if hops:
					nak.SetOption('hops',hops)
				if giaddr != '0.0.0.0':
					self.SendPacket( nak )
				elif ciaddr != '0.0.0.0':
					self.SendPacket( nak, dest=ciaddr )
				elif requested_ip != '0.0.0.0':
					self.SendPacket( nak, dest=requested_ip )
				else:
					self.SendPacket( nak )
				# FIXME: We aren't handling this right... or somethink...
				return

			ack = DhcpPacket()
			ack.CreateDhcpAckPacketFrom(packet)
			# make a list of requested DHCP options
			requested_options = packet.GetOption('parameter_request_list')
			print "requested_options: %s" % requested_options

			if lease['hostname'] and DhcpOptions['host_name'] in requested_options:
				ack.SetOption("host_name", map(ord,lease['hostname']))
			
			# get option/value pairs from database
			opt_vals = self.__db.retrieve_dhcp_options( mac=mac, address=requested_ip, option_ids = requested_options )
			print "opt_vals: %s" % str(opt_vals)

			print 'Got lease %s from database' % lease
			# set them on the packet
			# Options to request from the DB (address/gateway are assumed)
			ack.SetOption("yiaddr",ip_to_list(lease['address']))

			hops = packet.GetOption('hops')
			if hops:
				ack.SetOption('hops',hops)
			ack.SetOption("ip_address_lease_time",int_to_4_bytes(lease['lease_time'])) # TEST
			ack.SetOption("subnet_mask",ip_to_list(lease['netmask']))
			ack.SetOption("broadcast_address",ip_to_list(lease['broadcast'])) # TEST
			ack.SetOption("router",ip_to_list(lease['router']))

			for opt in opt_vals:
				ack.SetOption( DhcpRevOptions[opt['oid']], bytes_to_ints( opt['value'] ) )
				print "Setting %s to '%s'" % ( DhcpRevOptions[opt['oid']], bytes_to_ints( opt['value'] ) )
				# Use tftp-server for next-server == sname
				if opt['oid'] == 66:
					ack.SetOption("sname", opt['value'])
					print "Setting next-server to '%s'" % ( bytes_to_ints( opt['value'] ) )

			# send an ack
			print "  > sending ack"
			self.SendPacket(ack)
			
			print "#############################################################################"

	dhcp_handler = dhcp_packet_handler( send_packet )

	#my_logfile = '/var/log/dhcp/dhcp_server_worker.%s' % os.getpid()
	#logfile = open( my_logfile, 'a' )
	#logfile.write('Starting worker process.\n')
	#os.dup2( logfile.fileno(), sys.stdout.fileno() )

	while True:
		try:
			# FIXME: for production, this should be in a try/except block
			pkttype, pkt = dbq.get()
			# Handle request
			dhcp_handler.handle_packet( pkt, type=pkttype )	
		except error.NotFound, e:
			#print_exception( e, traceback=False )
			print 'sorry'
			print str(e)
		except Exception,e:
			print_exception( e )
	
	#logfile.close()

def print_exception( exc, traceback = True ):
	import traceback
	# FIXME: Do some syslogging here
	if traceback:
		#traceback_file = '/var/log/dhcp/tracebacks'
		traceback_file = dhcp.traceback_file
		tb_file = open( traceback_file, 'a' )
		traceback.print_exc( file = tb_file )
		tb_file.write( str(exc) )
		tb_file.close()
		traceback.print_exc()
	print str(exc)


