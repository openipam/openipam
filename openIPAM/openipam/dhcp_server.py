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

import select

from pydhcplib.dhcp_constants import DhcpOptions

# FIXME: don't 'import *'
from pydhcplib.dhcp_packet import *
from pydhcplib.dhcp_network import *

import IN

#from pydhcplib.dhcp_packet import DhcpPacket
#import dhcp_packet
#import dhcp_network
#from pydhcplib.type_strlist import strlist
#from pydhcplib.type_ipv4 import ipv4

import datetime
import time

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

def get_packet_type( packet ):
	_type = None
	if packet.IsOption("dhcp_message_type"):
		_type = bytes_to_int( packet.GetOption("dhcp_message_type") )
	return _type
	
class Server():
	BUFLEN=8192
	listen_bcast = '0.0.0.0'
	listen_port = 67
	bootpc_port = 68
	bootps_port = 67
	def __init__(self, dbq):
		self.__dbq = dbq
		#self.last_seen = {}
		self.seen = {}
		self.seen_cleanup = []
		self.dhcp_sockets = []
		self.dhcp_socket_info = {}
		self.dhcp_unicast_xmit_socket = socket.socket()
		self.dhcp_xmit_socket = None # initialize this in the sender

		if not dhcp.server_listen:
			raise Exception("Missing configuration option: openipam_config.dhcp.server_listen")

		for s in dhcp.server_listen:
			if s['broadcast']:
				bsocket_info = s.copy()
				bsocket_info['unicast'] = False
				bsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				bsocket.setsockopt(socket.SOL_SOCKET,IN.SO_BINDTODEVICE, bsocket_info['interface'])
				bsocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
				bsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				bsocket.bind( (self.listen_bcast, self.listen_port) )
				self.dhcp_sockets.append(bsocket)
				self.dhcp_socket_info[bsocket] = bsocket_info
			if s['unicast']:
				usocket_info = s.copy()
				usocket_info['broadcast'] = False
				usocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				usocket.setsockopt(socket.SOL_SOCKET,IN.SO_BINDTODEVICE, usocket_info['interface'])
				usocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				usocket.bind( (usocket_info['address'], self.listen_port) )
				self.dhcp_sockets.append(usocket)
				self.dhcp_socket_info[usocket] = usocket_info

	def HandlePacket( self ):
		rlist, wlist, xlist = select.select(self.dhcp_sockets, [], [])
		s = rlist[0]
		data,sender = s.recvfrom(self.BUFLEN)

		packet = dhcp_packet.DhcpPacket()
		packet.DecodePacket(data)
		packet.set_sender( sender )
		packet.set_recv_interface( self.dhcp_socket_info[s] )

		packet_type = get_packet_type( packet )
		self.QueuePacket( packet, packet_type )

	def SendPacket(self, packet, bootp = False, giaddr=None):
		"""Encode and send the packet."""

		if not self.dhcp_xmit_socket:
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
			s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			s.bind( (self.listen_bcast, self.listen_port) )
			self.dhcp_xmit_socket = s

		#sender = packet.get_sender()
		if giaddr is None:
			giaddr = '.'.join(map(str,packet.GetOption('giaddr')))
		ciaddr = '.'.join(map(str,packet.GetOption('ciaddr')))
		yiaddr = '.'.join(map(str,packet.GetOption('yiaddr')))
		chaddr = decode_mac( packet.GetOption('chaddr') )

		if not bootp:
			server_id = map(int, packet.get_recv_interface()['address'].split('.'))
			packet.SetOption("server_identifier",server_id) # DHCP server IP

		# See rfc1532 page 21
		if ciaddr != '0.0.0.0':
			log_packet(packet, prefix='SND/CIADDR:')
			dest = ( ciaddr, self.bootpc_port )
		elif giaddr != '0.0.0.0':
			log_packet(packet, prefix='SND/GIADDR:')
			dest = ( giaddr, self.bootps_port )
		elif yiaddr != '0.0.0.0':
			broadcast = packet.GetOption('flags')[0] >> 7

			if broadcast:
				log_packet(packet, prefix='SND/BCAST:')
				dest = ( '255.255.255.255', self.bootpc_port )
			else:
				# FIXME: need to send this directly to chaddr :/
				#log_packet(packet, prefix='SND/CHADDR:')
				#dest = ( yiaddr, self.bootpc_port ) 
				try:
					os.system("arp -H ether -i %s -s %s %s temp" % (self.dhcp_iface, yiaddr, chaddr))
					log_packet(packet, prefix='SND/ARPHACK:')
					dest = ( yiaddr, self.bootpc_port )
				except:
					log_packet(packet, prefix='SND/HACK:')
					dest = ( '255.255.255.255', self.bootpc_port )
		else:
			log_packet(packet, prefix='IGN/SNDFAIL:', level=dhcp.logging.ERROR)
			raise Exception('Cannot send packet without one of ciaddr, giaddr, or yiaddr.')

		self.dhcp_xmit_socket.sendto( packet.EncodePacket(), dest )

		if show_packets:
			print "------- Sending Packet ----------"
			print sender
			packet.PrintHeaders()
			packet.PrintOptions()
			print "---------------------------------"
	
	def do_seen_cleanup( self, mac, min_timestamp ):
		if not self.seen.has_key( mac ):
			self.seen[mac] = []
		seen = self.seen[ mac ]

		# do some cleanup on our mac
		while seen and seen[0][0] < min_timestamp:
			del seen[0]

		# do a little bit of housekeeping while we're at it
		if self.seen_cleanup:
			cleanup_mac = self.seen_cleanup.pop()
			while self.seen[ cleanup_mac ] and self.seen[ cleanup_mac ][0][0] < min_timestamp:
				del self.seen[ cleanup_mac ][0]
			if not self.seen[ cleanup_mac ]:
				del self.seen[ cleanup_mac ]
		else:
			self.seen_cleanup = self.seen.keys()

		return seen

	def QueuePacket( self, packet, pkttype ):
		mac = decode_mac( packet.GetOption('chaddr') )
		c_time=datetime.datetime.now()

		# Minimum time between allowing a user to make the same kind of request
		#BETWEEN_REQUESTS = datetime.timedelta(days=0,minutes=0,seconds=10)
		TIME_PERIOD = datetime.timedelta(days=0,minutes=1,seconds=0)

		#types = { None:'bootp', 1:'discover', 2:'offer', 3:'request', 4:'decline', 5:'ack', 6:'nak', 7:'release', 8:'inform', }
		MESSAGE_TYPE_LIMIT = { None:2, 1:6, 3:10, 4:12, 7:20, 8:16  } # we are only counting serviced packets, regardless of type
		
		if MESSAGE_TYPE_LIMIT.has_key(pkttype):
			MAX_REQUESTS = MESSAGE_TYPE_LIMIT[pkttype]
		else:
			MAX_REQUESTS = 0

		#our_key = (mac, pkttype,)

		# Thanks to the morons at MS, we can't do this.
		# see http://support.microsoft.com/kb/835304 for more info
		# FIXME: find another way to prevent DoS.
		#if self.last_seen.has_key( our_key ):
		#	time = self.last_seen[ our_key ]
		#	if ( ( c_time - time ) < dhcp.between_requests ):
		#		print "ignoring request type %s from mac %s because we saw a request at %s (current: %s)" % (pkttype, mac, str(time), str(c_time))
		#		log_packet( packet, prefix='IGN/TIME:' )
		#		return
		#	else:
		#		del self.last_seen[ our_key ]

		min_timestamp = c_time - TIME_PERIOD

		seen = self.do_seen_cleanup( mac, min_timestamp )

		if len(seen) > MAX_REQUESTS:
				log_packet( packet, prefix='IGN/LIMIT:', level=dhcp.logging.WARNING )
				print "ignoring request type %s from mac %s because we have seen %s requests in %s" % (pkttype, mac, len(seen), str(TIME_PERIOD))
				return
		
		packet.retry_count = 0
		packet.last_retry = 0

		try:
			log_packet( packet, prefix='QUEUED:' )
			self.__dbq.put_nowait( (pkttype, packet) )
		except Full, e:
			# The queue is full, try again later.
			log_packet( packet, prefix='IGN/FULL:', level=dhcp.logging.ERROR )
			print "ignoring request type %s from mac %s because the queue is full ... be afraid" % (pkttype,mac)
			return
		
		# If we get here, the packet should be in the queue, so we can
		# guarantee it will be seen by one of the workers.  Let's add
		# this to our list of things we don't want to respond to right
		# now.
		#self.last_seen[ our_key ] = ( c_time )
		seen.append( (c_time, pkttype,) )


def parse_packet( packet ):
	pkttype = get_packet_type(packet)
	mac = decode_mac( packet.GetOption('chaddr') )
	xid = bytes_to_int( packet.GetOption('xid') )
	requested_options = packet.GetOption('parameter_request_list')

	if hasattr(dhcp, 'force_options') and dhcp.force_options:
		requested_options.extend(dhcp.force_options)

	recvd_from = packet.get_sender()
	giaddr = '.'.join(map(str,packet.GetOption('giaddr')))

	client_ip = '.'.join(map(str,packet.GetOption('yiaddr')))
	if client_ip == '0.0.0.0':
		client_ip = '.'.join(map(str,packet.GetOption('ciaddr')))
		if client_ip == '0.0.0.0':
			x = packet.GetOption('request_ip_address')
			if x:
				client_ip = '.'.join(map(str,x))
			else:
				client_ip = packet.get_sender()[0]
	
	return (pkttype, mac, xid, client_ip, giaddr, recvd_from, requested_options)

types = { None:'bootp', 1:'discover', 2:'offer', 3:'request', 4:'decline', 5:'ack', 6:'nak', 7:'release', 8:'inform', }

def log_packet( packet, prefix='', level=dhcp.logging.INFO):
	# This should be called for every incoming or outgoing packet.
	pkttype,mac,xid,client,giaddr,recvd_from,req_opts = parse_packet(packet)

	t_name = types[pkttype]

	if giaddr != '0.0.0.0':
		client_foo = '%s via %s' % (client, giaddr)
	else:
		client_foo = str(client)

	dhcp.get_logger().log(level, "%-12s %-8s %s 0x%08x (%s)", prefix, t_name, mac, xid, client_foo )

def db_consumer( dbq, send_packet ):
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
				dhcp.get_logger().log(dhcp.logging.ERROR, "%-12s Address in use: %s", 'ERR/DECL:', requested_ip )
				self.__db.mark_abandoned_lease( mac=mac, address=requested_ip )
			else:
				dhcp.get_logger().log(dhcp.logging.ERROR, "%-12s Address in use: %s", 'ERR/DECL2:', mac )
				self.__db.mark_abandoned_lease( mac=mac )

		def dhcp_release(self, packet):
			mac = decode_mac( packet.GetOption('chaddr') )
			log_packet( packet, prefix='IGN/REL:' )

		def assign_dhcp_options(self, options, requested, packet):
			opt_vals = {}
			for o in options:
				if o['value'] is None: # unset this option, plz
					packet.DeleteOption(DhcpRevOptions[o['oid']])
					if opt_vals.has_key(int(o['oid'])):
						del opt_vals[ int(o['oid']) ]
				else:
					opt_vals[ int(o['oid']) ] = o['value']

			preferred = []
			for oid in requested:
				if DhcpRevOptions.has_key(oid):
					preferred.append( DhcpRevOptions[oid] )

			packet.options_data.set_preferred_order( preferred )

			for i in opt_vals.keys():
				packet.SetOption( DhcpRevOptions[i], bytes_to_ints( opt_vals[i] ) )
				print "Setting %s to '%s'" % ( DhcpRevOptions[i], bytes_to_ints( opt_vals[i] ) )
				# Use  for next-server == siaddr
				if i == 11:
					packet.SetOption("siaddr", bytes_to_ints( opt_vals[i] ) )
					print "Setting next-server (siaddr) to '%s'" % ( bytes_to_ints( opt_vals[i] ) )
				# Use tftp-server for next-server == sname
				if i == 66:
					v = str(opt_vals[i])

					v_padded = v + '\0'*(64-len(v)) # pydhcplib is too lame to do this for us
					packet.SetOption("sname", bytes_to_ints(v_padded) )
					print "Setting sname to '%s'" % ( bytes_to_ints( v ) )
					try:
						host = self.__db.get_dns_records(tid=1,name=v)[0]
						addr = map(int,host['ip_content'].split('.'))
						packet.SetOption("siaddr", addr )
						print "Setting next-server (siaddr) to '%s'" % ( addr )
					except:
						pass
				# Use tftp file name for bootfile
				if i == 67:
					v = opt_vals[i]
					v = v + '\0'*(128-len(v)) # pydhcplib is too lame to do this for us
					packet.SetOption("file", bytes_to_ints(v) )
					print "Setting next-server to '%s'" % ( bytes_to_ints( v ) )
					#print "Adding padding for lame fujitsu PXE foo"
					# This doesn't work because pydhcplib sucks
					#packet.SetOption("pad",'')

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
			
			self.assign_dhcp_options( options=opt_vals, requested=requested_options, packet=ack )

			# send an ack
			self.SendPacket( ack )
		
		def dhcp_discover(self, packet):
			router = '.'.join(map(str,packet.GetOption('giaddr')))
			mac = decode_mac( packet.GetOption('chaddr') )
			requested_ip = '.'.join(map(str,packet.GetOption('request_ip_address')))
			
			recv_if = packet.get_recv_interface()
			if router == '0.0.0.0':
				if recv_if['broadcast']:
					# hey, local DHCP traffic!
					router = recv_if['address']

			if not requested_ip:
				requested_ip = '.'.join(map(str,packet.GetOption('ciaddr')))
				if not requested_ip:
					raise Exception("This really needs fixed...")

			lease = self.__db.make_dhcp_lease(mac, router, requested_ip, discover=True, server_address = recv_if['address'])
			
			print 'Got lease %s from database' % lease

			while self.address_in_use( lease['address'] ):
				print 'Address %s in use, marking lease %s as abandoned' % ( lease['address'], lease )
				dhcp.get_logger().log(dhcp.logging.ERROR, "%-12s Address in use: %(15)s", 'ERR/IN_USE:', lease['address'] )
				self.__db.mark_abandoned_lease( address=lease['address'] )
				lease = self.__db.make_dhcp_lease(mac, router, requested_ip, discover=True, server_address = recv_if['address'])
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

			# get option/value pairs from database
			opt_vals = self.__db.retrieve_dhcp_options( mac=mac, address=requested_ip, option_ids = requested_options )
			print "opt_vals: %s" % str(opt_vals)

			self.assign_dhcp_options( options=opt_vals, requested=requested_options, packet=offer )

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

			recv_if = packet.get_recv_interface()
			if router == '0.0.0.0':
				if recv_if['broadcast']:
					# hey, local DHCP traffic!
					router = recv_if['address']

			# FIXME: If ciaddr is set, we should use a unicast message to the client

			requested_ip = '.'.join(map(str,packet.GetOption('request_ip_address')))
			if not requested_ip:
				requested_ip = ciaddr
				if not requested_ip:
					raise Exception("This really needs fixed...")

			if router == '0.0.0.0' and recv_if['unicast']:
				# this was a unicast packet, I hope...
				router = requested_ip

			giaddr = '.'.join(map(str, packet.GetOption('giaddr')))

			print "mac: %s, requested address: %s" % (mac, requested_ip)
			# make sure a valid lease exists

			try:
				lease = self.__db.make_dhcp_lease(mac, router, requested_ip, discover=False, server_address = recv_if['address'])
			except error.InvalidIPAddress, e:
				lease = {'address': None, 'error': 'address not allowed for client'}
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
				self.SendPacket(nak, giaddr=router)
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

			self.assign_dhcp_options( options=opt_vals, requested=requested_options, packet=ack )

			# send an ack
			print "  > sending ack"
			self.SendPacket(ack)
			
			print "#############################################################################"

	dhcp_handler = dhcp_packet_handler( send_packet )

	#my_logfile = '/var/log/dhcp/dhcp_server_worker.%s' % os.getpid()
	#logfile = open( my_logfile, 'a' )
	#logfile.write('Starting worker process.\n')
	#os.dup2( logfile.fileno(), sys.stdout.fileno() )

	# FIXME: don't create sqlalchemy db connection foo at global module level so we don't have to hack like this
	from openipam.backend.db import interface

	REQUEUE_DELAY=0.2  # seconds
	REQUEUE_MAX=5  # number of attempts

	def requeue(p_type, packet):
		success = False
		try:
			dbq.put_nowait((p_type, packet))
			success = True
		except Full as e:
			print "Queue full, not requeueing"
			log_packet( packet, prefix='IGN/REQFAIL:', level=dhcp.logging.ERROR)
		return success

	while True:
		# FIXME: for production, this should be in a try/except block
		pkttype, pkt = dbq.get()
		try:
			# Handle request
			try:
				if (time.time() - pkt.last_retry) > REQUEUE_DELAY:
					dhcp_handler.handle_packet( pkt, type=pkttype )	
				else:
					requeue(pkttype, pkt)
			except interface.DHCPRetryError as e:
				pkt.retry_count += 1

				if pkt.retry_count <= REQUEUE_MAX:
					pkt.last_retry = time.time()
					# if the queue is full, we probably want to ignore this packet anyway
					print 're-queueing packet for retry: %r' % e
					if requeue(pkttype, pkt):
						log_packet( pkt, prefix='IGN/REQUEUE:', level=dhcp.logging.ERROR )
				else:
					print "dropping packet after too many retries: %r" % e
					log_packet( pkt, prefix='IGN/TOOMANY:', level=dhcp.logging.ERROR )

		except error.NotFound, e:
			#print_exception( e, traceback=False )
			print 'sorry, no lease found'
			log_packet( pkt, prefix='IGN/UNAVAIL:', level=dhcp.logging.ERROR )
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


