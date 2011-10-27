#!/usr/bin/env python

from twisted.internet import DatagramProtocol
from twisted.internet import udp
from twisted.internet import fdesc
from twisted.internet import deferred

from zope.interface import Interface

import struct

import IN

from openipam import dhcp_server

# TODO: find a way to send packets to a specified ethernet address

class DeferredDHCPRequest(defer.Deferred):
	def __init__(self, packet, port):
		self.packet = packet
		self.port = port

class DHCPProtocol(DatagramProtocol):
	def __init__(self, dhcp_handler):
		self.handler = dhcp_handler
	def handleDHCPPacket(self, packet, src_addr, port):
		ifname = port.ifname

		d = DeferredDHCPRequest(packet=packet, port=port)

	def startProtocol(self):
		pass
	def stopProtocol(self):
		pass
	def datagramReceived(self, datagram, addr, port):
		# we stray from the standard slightly here to try to figure out
		# which interface the packet came in on
		pass
	

class UDPBroadcastPort(udp.Port):
	def __init__(self, port, protocol, address='', maxPacketSize=8192, reactor=None, ifname=None):
		# For some reason, they called it 'interface' in the twisted code
		#  but 'address' is more accurate
		udp.Port.__init__(self, port, protocol, address, maxPacketSize, reactor)
		self.ifname = ifname
		self.addr = None
	def createInternetSocket(self):
		s = socket.socket(self.addressFamily, self.socketType)
		s.setblocking(0)
		fdesc._setCloseOnExec(s.fileno())

		# Socket should receive UDP broadcasts
		s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)

		if self.ifname:
			padded_iface = struct.pack('256s',self.ifname[:15])

			# Allow multiple sockets to listen on this address (ie. 0.0.0.0)
			# since we are listening on a single interface, and probably want
			# to listen on others
			s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)

			# Only recieve packets from the given interface
			s.setsockopt(socket.SOL_SOCKET,IN.SO_BINDTODEVICE,
					padded_ifname)

			# hopefully get the primary address on this interface
			addr = fcntl.ioctl(s.fileno(),
					0x8915,  # SIOCGIFADDR
					padded_iface)
			self.addr = socket.inet_ntoa( addr[20:24] )

		return s

	def doRead(self):
		"""
		Called when my socket is ready for reading.

		ripped off from twisted.internet.udp.doRead() to add an argument to the
		datagramReceived() call
		"""
		read = 0
		while read < self.maxThroughput:
			try:
				data, addr = self.socket.recvfrom(self.maxPacketSize)
			except socket.error, se:
				no = se.args[0]
				if no in (EAGAIN, EINTR, EWOULDBLOCK):
					return
				if (no == ECONNREFUSED) or (platformType == "win32" and no == WSAECONNRESET):
					if self._connectedAddr:
						self.protocol.connectionRefused()
				else:
					raise
			else:
				read += len(data)
				try:
					self.protocol.datagramReceived(data, addr, self)
				except:
					log.err()





