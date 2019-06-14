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
from .dhcp_constants import *

# DhcpPacket : base class to encode/decode dhcp packets.
try:
    # python3
    from collections import UserDict
except ImportError:
    # python2
    from UserDict import UserDict

# Lovingly ripped off from http://code.activestate.com/recipes/107747/

class odict(UserDict):
    def __init__(self, _dict = None):
        self._keys = []
        self._preferred_order = None
        UserDict.__init__(self, _dict)
        self._raw_data = None

    def __delitem__(self, key):
        UserDict.__delitem__(self, key)
        if self._preferred_order:
            if key in self._preferred_order:
                p_idx = self._preferred_order.index(key)
                self._keys[p_idx] = None
                return
        self._keys.remove(key)

    def __setitem__(self, key, item):
        if key == None:
            raise Exception('I don\'t know how to handle None as a key.')
        UserDict.__setitem__(self, key, item)
        if self._preferred_order and key in self._preferred_order:
            self._keys[self._preferred_order.index(key)] = key
        elif key not in self._keys: self._keys.append(key)

    def set_preferred_order(self, order):
        self._preferred_order = order[:]
        newkeys = [None] * len(self._preferred_order)
        for k in self._keys:
            if k in self._preferred_order:
                newkeys[self._preferred_order.index(k)] = k
            else:
                newkeys.append(k)
        self._keys = newkeys

    def clear(self):
        UserDict.clear(self)
        self._keys = []

    def copy(self):
        _dict = UserDict.copy(self)
        _dict._keys = self._keys[:]
        _dict._preferred_order = self._preferred_order[:]
        return _dict

    def items(self):
        return list(zip(list(self.keys()), list(self.values())))

    def keys(self):
        if self._preferred_order:
            l = len(self._preferred_order)
            # Put unknown keys first
            newkeys = self._keys[l:]
            for k in self._keys[:l]:
                if k is not None: newkeys.append(k)
        else:
            newkeys = self._keys[:]
        return newkeys

    def popitem(self):
        keys = list(self.keys())
        try:
            key = keys[-1]
        except IndexError:
            raise KeyError('dictionary is empty')

        val = self[key]
        del self[key]

        return (key, val)

    def setdefault(self, key, failobj = None):
        if key not in self._keys: self[key] = failobj
        UserDict.setdefault(self, key, failobj)

    def update(self, dict):
        for key in list(dict.keys()):
            self[key] = dict[key]

    def values(self):
        return list(map(self.get, list(self.keys())))


class DhcpBasicPacket:
    def __init__(self):
        self.packet_data = [0]*240
        self.options_data = odict()
        self.packet_data[236:240] = MagicCookie
        self.sender = None

    def IsDhcpPacket(self):
        if self.packet_data[236:240] != MagicCookie : return False
        return True

    # Check if variable is a list with int between 0 and 255
    def CheckType(self,variable):
        if type(variable) == list :
            for each in variable :
                if (type(each) != int)  or (each < 0) or (each > 255) :
                    return False
            return True
        else : return False

    def DeleteOption(self,name):
        # if name is a standard dhcp field
        # Set field to 0
        if name in DhcpFields :
            begin = DhcpFields[name][0]
            end = DhcpFields[name][0]+DhcpFields[name][1]
            self.packet_data[begin:end] = [0]*DhcpFields[name][1]
            return True

        # if name is a dhcp option
        # delete option from self.option_data
        elif name in self.options_data :
            # forget how to remove a key... try delete
            del self.options_data[name]
            return True

        return False

    def GetOption(self,name):
        if name in DhcpFields :
            option_info = DhcpFields[name]
            return self.packet_data[option_info[0]:option_info[0]+option_info[1]]

        elif name in self.options_data :
            return self.options_data[name]

        return []
        

    def SetOption(self,name,value):

        # Basic vlue checking :
        # has value list a correct length
        
        # if name is a standard dhcp field
        if name in DhcpFields :
            if len(value) != DhcpFields[name][1] :
                print("Error, bad option length (a): ", name)
                return False
            begin = DhcpFields[name][0]
            end = DhcpFields[name][0]+DhcpFields[name][1]
            self.packet_data[begin:end] = value
            return True

        # if name is a dhcp option
        elif name in DhcpOptions :

            # fields_specs : {'option_code',fixed_length,minimum_length,multiple}
            # if fixed_length == 0 : minimum_length and multiple apply
            # else : forget minimum_length and multiple 
            # multiple : length MUST be a multiple of 'multiple'
            fields_specs = { "ipv4":[4,0,1], "ipv4+":[0,4,4],
                             "string":[0,0,1], "bool":[1,0,1],
                             "char":[1,0,1], "16-bits":[2,0,1],
                             "32-bits":[4,0,1], "identifier":[0,2,1]}
            
            specs = fields_specs[DhcpOptionsTypes[DhcpOptions[name]]]
            length = len(value)
            if (specs[0]!=0 and specs==length) or (specs[1]<=length and length%specs[2]==0):
                self.options_data[name] = value
                return True
            else :
                return False

        print("Error, unknown option : ", name, value)
        return False



    def IsOption(self,name):
        if name in self.options_data : return True
        elif name in DhcpFields : return True
        else : return False


    # Encode Packet and return it
    def EncodePacket(self):
        options = []
        
        # RFC 3046 says relay_agent SHOULD be last
        keys = list(self.options_data.keys())
        if 'relay_agent' in keys:
            idx = keys.index('relay_agent')
            del keys[idx]
            keys.append('relay_agent')

        for each in list(self.options_data.keys()) :
            options.append(DhcpOptions[each])
            options.append(len(self.options_data[each]))
            options.extend(self.options_data[each])
            if DhcpOptions[each] == 67:
                # we have a bunch of crap that reuse buffers they shouldn't,
                #   so add a null for them here
                options.append(0)

        packet = self.packet_data[:240] + options
        packet.append(255) # add end option
        pktlen = len(packet)
        if pktlen < 300:
            packet.extend([0] * (300-pktlen)) # RFC says min packet size is 300

        packet = list(map(chr,packet))

        pack_fmt = str(len(packet))+"c"
        
        return pack(pack_fmt,*packet)


    # Insert packet in the object
    def DecodePacket(self,data,debug=False):
        self._raw_data = data[:] if data else None
        self.packet_data = []
        self.options_data = {}

        if (not data) : return False
        # we transform all data to int list
        unpack_fmt = str(len(data)) + "c"
        for i in unpack(unpack_fmt,data):
            self.packet_data.append(ord(i))
        if ( debug ) : print("Packet length : ",len(self.packet_data))


        # Some servers or clients don't place magic cookie immediately
        # after headers and begin options fields only after magic.
        # These 4 lines search magic cookie and begin iterator after.
        iterator = 236
        end_iterator = len(self.packet_data)
        while ( self.packet_data[iterator:iterator+4] != MagicCookie and iterator < end_iterator) :
            iterator += 1
        iterator += 4
        
        # parse extended options
        if ( debug ) : print("Debug : ", self.packet_data[iterator:-1])


        while iterator < end_iterator :
            if ( debug ) :
                print("Debug Option : ", iterator , self.packet_data[iterator]," : ",DhcpOptionsList[self.packet_data[iterator]])
            if self.packet_data[iterator] == 0 : # pad option
                opt_first = iterator+1
                iterator += 1

            elif self.packet_data[iterator] == 255 :
                self.packet_data = self.packet_data[:240] # base packet length without magic cookie
                return
                
            elif self.packet_data[iterator] in DhcpOptionsTypes and self.packet_data[iterator]!= 255:
                opt_len = self.packet_data[iterator+1]
                opt_first = iterator+1
                self.options_data[DhcpOptionsList[self.packet_data[iterator]]] = self.packet_data[opt_first+1:opt_len+opt_first+1]
                iterator += self.packet_data[opt_first] + 2
            else :
                opt_first = iterator+1
                iterator += self.packet_data[opt_first] + 2

        # cut packet_data to remove options
        
        self.packet_data = self.packet_data[:240] # base packet length with magic cookie
