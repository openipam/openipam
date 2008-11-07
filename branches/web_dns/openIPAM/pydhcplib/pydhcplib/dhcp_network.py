# pydhcplib
# Copyright (C) 2005,2006 Mathieu Ignacio -- mignacio@april.org
#
# This file is part of pydhcplib.
# Pydhcplib is free software; you can redistribute it and/or modify
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA

import sys
import socket
import dhcp_packet


class DhcpNetwork:
    def __init__(self, listen_address="0.0.0.0", listen_port=67, emit_port=68):

        self.listen_port = int(listen_port)
        self.emit_port = int(emit_port)
        self.listen_address = listen_address
        
    def GetNextDhcpPacket(self):
        data =""

        while data == "" :
            data = self.dhcp_socket.recv(1024)
            if data != "" :
                packet = dhcp_packet.DhcpPacket()
                packet.DecodePacket(data)

                self.HandleDhcpAll(packet)
                
                if packet.IsDhcpDiscoverPacket():
                    self.HandleDhcpDiscover(packet)
                elif packet.IsDhcpRequestPacket():
                    self.HandleDhcpRequest(packet)
                elif packet.IsDhcpDeclinePacket():
                    self.HandleDhcpDecline(packet)
                elif packet.IsDhcpReleasePacket():
                    self.HandleDhcpRelease(packet)
                elif packet.IsDhcpInformPacket():
                    self.HandleDhcpInform(packet)
                elif packet.IsDhcpOfferPacket():
                    self.HandleDhcpOffer(packet)
                elif packet.IsDhcpAckPacket():
                    self.HandleDhcpAck(packet)
                elif packet.IsDhcpNackPacket():
                    self.HandleDhcpNack(packet)
                else: self.HandleDhcpUnknown(packet)

                return packet


    def SendDhcpPacketTo(self, To, packet, port=None):
        if not port:
            port = self.emit_port
        return self.dhcp_socket.sendto(packet.EncodePacket(),(To,port))


    # Server side Handle methods
    def HandleDhcpDiscover(self, packet):
        print "HandleDhcpRequest : method not implemented"

    def HandleDhcpRequest(self, packet):
        print "HandleDhcpRequest : method not implemented"

    def HandleDhcpDecline(self, packet):
        print "HandleDhcpDecline : method not implemented"

    def HandleDhcpRelease(self, packet):
        print "HandleDhcpRelease : method not implemented"

    def HandleDhcpInform(self, packet):
        print "HandleDhcpInform : method not implemented"


    # client-side Handle methods
    def HandleDhcpOffer(self, packet):
        print "HandleDhcpOffer : method not implemented"
        
    def HandleDhcpAck(self, packet):
        print "HandleDhcpAckhandling : method not implemented"

    def HandleDhcpNack(self, packet):
        print "HandleDhcpNack : method not implemented"


    # Handle unknown options or all options
    def HandleDhcpUnknown(self, packet):
        print "HandleDhcpUnknown : method not implemented"

    def HandleDhcpAll(self, packet):
        pass


class DhcpServer(DhcpNetwork) :
    def __init__(self, listen_address="0.0.0.0", client_listen_port=67,server_listen_port=68) :
        
        DhcpNetwork.__init__(self,listen_address,server_listen_port,client_listen_port)
        
        self.dhcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dhcp_socket.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        self.dhcp_socket.bind((self.listen_address, self.listen_port))


class DhcpClient(DhcpNetwork) :
    def __init__(self, listen_address="0.0.0.0",client_listen_port=67,server_listen_port=68) :

        DhcpNetwork.__init__(self,listen_address,client_listen_port,server_listen_port)

        self.dhcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dhcp_socket.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        self.dhcp_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.dhcp_socket.bind((self.listen_address, self.listen_port))

# Raw client permit to listen on network even if there is
# no interface set. Probably useful... :-)
class DhcpRawClient(DhcpNetwork) :
    def __init__(self, interface="eth0", client_listen_port=67,server_listen_port=68) :

        DhcpNetwork.__init__(self,interface,client_listen_port,server_listen_port)
        print interface
                # 0x800 : ETH_P_IP, 0x003 : ETH_P_ALL
        # See Linux/if_ether.h 
        self.dhcp_socket = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM,socket.ntohs(0x0800))

            
