# Anemon Dhcp
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA

import operator
from struct import unpack
from struct import pack
from .dhcp_basic_packet import *
from .dhcp_constants import *
from .type_ipv4 import ipv4
from .type_strlist import strlist
import base64

class DhcpPacket(DhcpBasicPacket):
    _raw_data = None

    def set_sender(self, sender):
        self.sender = sender

    def get_sender( self ):
        return self.sender

    def set_recv_interface( self, info ):
        self.recv_interface = info

    def get_recv_interface( self ):
        return self.recv_interface

    # Useful function for debugging
    def PrintHeaders(self):
        print("# Header fields\n")
        print("readable_dhcp_headers = {")
        for opt in  ['op','htype','hlen','hops','xid','secs','flags',
                     'ciaddr','yiaddr','siaddr','giaddr','chaddr','sname','file'] :
            begin = DhcpFields[opt][0]
            end = DhcpFields[opt][0]+DhcpFields[opt][1]
            data = self.packet_data[begin:end]
            if DhcpFieldsTypes[opt] == "int" : result = str(data[0])
            if DhcpFieldsTypes[opt] == "int2" : result = str(data[0]*256+data[0])
            if DhcpFieldsTypes[opt] == "int4" : result = str(ipv4(data).int())
            if DhcpFieldsTypes[opt] == "str" : result = strlist(data).str()
            if DhcpFieldsTypes[opt] == "ipv4" : result = ipv4(data).str()
            if DhcpFieldsTypes[opt] == "hwmac" : result = "".join(map(chr,data))

            line = "\t'"+opt+"':"+str(data)+",\t# "+result
            print(line)
        print("\t'end':'true'}")

    # Useful function for debugging
    def PrintOptions(self):
        print("# Options fields")
        print("readable_dhcp_options = {")
        for opt in list(self.options_data.keys()):
            data = self.options_data[opt]
            result = ""
            optnum  = DhcpOptions[opt]
            if DhcpOptionsTypes[optnum] == "char" : result = str(data[0])
            if DhcpOptionsTypes[optnum] == "16-bits" : result = str(data[0]*256+data[0])
            if DhcpOptionsTypes[optnum] == "32bits" : result = str(ipv4(data).int())
            if DhcpOptionsTypes[optnum] == "string" : result = strlist(data).str()
            if DhcpOptionsTypes[optnum] == "ipv4" : result = ipv4(data).str()
            if DhcpOptionsTypes[optnum] == "ipv4+" :
                for i in range(0,len(data),4) :
                    if len(data[i:i+4]) == 4 :
                        result += ipv4(data[i:i+4]).str() + " - "
            line = "\t'"+opt+"':"+str(data)+",\t# "+result
            print(line)
        print("\t'end':'true'}")
        

            
    # FIXME: This is called from IsDhcpSomethingPacket, but is this really
    # needed?  Or maybe this testing should be done in
    # DhcpBasicPacket.DecodePacket().

    # Test Packet Type
    def IsDhcpSomethingPacket(self,type):
        if self.IsDhcpPacket() == False : return False
        if self.IsOption("dhcp_message_type") == False : return False
        if self.GetOption("dhcp_message_type") != type : return False
        return True
    
    def IsDhcpDiscoverPacket(self):
        return self.IsDhcpSomethingPacket([1])

    def IsDhcpOfferPacket(self):
        return self.IsDhcpSomethingPacket([2])

    def IsDhcpRequestPacket(self):
        return self.IsDhcpSomethingPacket([3])

    def IsDhcpDeclinePacket(self):
        return self.IsDhcpSomethingPacket([4])

    def IsDhcpAckPacket(self):
        return self.IsDhcpSomethingPacket([5])

    def IsDhcpNackPacket(self):
        return self.IsDhcpSomethingPacket([6])

    def IsDhcpReleasePacket(self):
        return self.IsDhcpSomethingPacket([7])

    def IsDhcpInformPacket(self):
        return self.IsDhcpSomethingPacket([8])


    def GetMultipleOptions(self,options=()):
        result = {}
        for each in options:
            result[each] = self.GetOption(each)
        return result

    def SetMultipleOptions(self,options={}):
        for each in list(options.keys()):
            self.SetOption(each,options[each])


    def CopyDhcpValuesFrom(self, src, additional_fields=[]):
        to_copy = ["htype", "xid", "flags", "giaddr", "chaddr", "relay_agent", ]
        to_copy.extend(additional_fields)

        for option in to_copy:
            if src.IsOption(option):
                self.SetOption(option, src.GetOption(option))

        self.set_sender(src.get_sender())
        self.set_recv_interface( src.get_recv_interface() )


    # Creating Response Packet

    # Server-side functions
    # From RFC 2132 page 28/29
    def CreateDhcpOfferPacketFrom(self,src): # src = discover packet
        self.CopyDhcpValuesFrom(src, ["ip_address_lease_time", ])

        self.TransformToDhcpOfferPacket()

    def TransformToDhcpOfferPacket(self):
        self.SetOption("dhcp_message_type",[2])
        self.SetOption("op",[2])
        self.SetOption("hlen",[6]) 

        self.DeleteOption("secs")
        self.DeleteOption("ciaddr")
        self.DeleteOption("request_ip_address")
        self.DeleteOption("parameter_request_list")
        self.DeleteOption("client_identifier")
        self.DeleteOption("maximum_message_size")





    """ Dhcp ACK packet creation """
    def CreateDhcpAckPacketFrom(self,src): # src = request or inform packet
        self.CopyDhcpValuesFrom(src, ["ciaddr", "ip_address_lease_time", ])

        self.TransformToDhcpAckPacket()

    def TransformToDhcpAckPacket(self): # src = request or inform packet
        self.SetOption("op",[2])
        self.SetOption("hlen",[6]) 
        self.SetOption("dhcp_message_type",[5])

        self.DeleteOption("secs")
        self.DeleteOption("request_ip_address")
        self.DeleteOption("parameter_request_list")
        self.DeleteOption("client_identifier")
        self.DeleteOption("maximum_message_size")


    """ Dhcp NACK packet creation """
    def CreateDhcpNackPacketFrom(self,src): # src = request or inform packet
        self.CopyDhcpValuesFrom(src)
        
        self.TransformToDhcpNackPacket()

    def TransformToDhcpNackPacket(self):
        self.SetOption("op",[2])
        self.SetOption("hlen",[6]) 
        self.DeleteOption("secs")
        self.DeleteOption("ciaddr")
        self.DeleteOption("yiaddr")
        self.DeleteOption("siaddr")
        self.DeleteOption("sname")
        self.DeleteOption("file")
        self.DeleteOption("request_ip_address")
        self.DeleteOption("ip_address_lease_time")
        self.DeleteOption("parameter_request_list")
        self.DeleteOption("client_identifier")
        self.DeleteOption("maximum_message_size")
        self.SetOption("dhcp_message_type",[6])







    """ GetClientIdentifier """

    def GetClientIdentifier(self) :
        if self.IsOption("client_identifier") :
            return self.GetOption("client_identifier")
        return []

    def GetGiaddr(self) :
        return self.GetOption("giaddr")

    def GetHardwareAddress(self) :
        length = self.GetOption("hlen")[0]
        full_hw = self.GetOption("chaddr")
        if length!=[] and length<len(full_hw) : return full_hw[0:length]
        return full_hw

    def __repr__(self) :
        return f"<{self.__class__}: originally decoded from: {base64.b64encode(self._raw_data) if self._raw_data else None!r}>"
