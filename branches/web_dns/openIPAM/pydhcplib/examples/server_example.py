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

from pydhcplib.dhcp_packet import *
from pydhcplib.dhcp_network import *


netopt = {'client_listen_port':"68",
           'server_listen_port':"67",
           'listen_address':"0.0.0.0"}

class Server(DhcpServer):
    def __init__(self, options):
        DhcpServer.__init__(self,options["listen_address"],
                            options["client_listen_port"],
                            options["server_listen_port"])
        
    def HandleDhcpDiscover(self, packet):
        packet.PrintHeaders()
        packet.PrintOptions()
        
    def HandleDhcpRequest(self, packet):
        packet.PrintHeaders()
        packet.PrintOptions()

    def HandleDhcpDecline(self, packet):
        packet.PrintHeaders()
        packet.PrintOptions()
        
    def HandleDhcpRelease(self, packet):
        packet.PrintHeaders()
        packet.PrintOptions()
        
    def HandleDhcpInform(self, packet):
        packet.PrintHeaders()
        packet.PrintOptions()



server = Server(netopt)

while True :
    server.GetNextDhcpPacket()
