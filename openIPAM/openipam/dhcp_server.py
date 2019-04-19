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

import base64

from pydhcplib.dhcp_constants import DhcpOptions

# FIXME: don't 'import *'
from pydhcplib.dhcp_packet import *
from pydhcplib.dhcp_network import *

# asm/sockios.h (this was removed from IN module for some reason?)
SO_BINDTODEVICE = 25


# from pydhcplib.dhcp_packet import DhcpPacket
# import dhcp_packet
# import dhcp_network
# from pydhcplib.type_strlist import strlist
# from pydhcplib.type_ipv4 import ipv4

import datetime
import time

# from pydhcplib.dhcp_backend import *
# from event_logger import Log

# from openipam.backend.db import interface
from openipam.utilities import error
from openipam.config import dhcp

raven_client = None
if dhcp.sentry_url:
    import raven

    raven_client = raven.Client(dhcp.sentry_url)

raven_client_min_level = dhcp.logging.ERROR

import subprocess

try:
    # python3
    from queue import Full, Empty
except ImportError:
    # python2
    from Queue import Full, Empty


def bytes_to_ip(packet, opt_name):
    try:
        addr = packet.GetOption(opt_name)
    except:
        addr = None

    if not addr:
        return None

    if type(addr) != list:
        raise Exception("Eh?")

    if len(addr) != 4:
        logger = dhcp.get_logger()
        dhcp.get_logger().log(
            dhcp.logging.ERROR,
            "INVALID: %r invalid for %s from %s"
            % (addr, opt_name, decode_mac(packet.GetOption("chaddr"))),
        )

        return None
    return ".".join(map(str, addr))


DhcpRevOptions = {}
for key in list(DhcpOptions.keys()):
    DhcpRevOptions[DhcpOptions[key]] = key

####
show_packets = False

####


def decode_mac(mac):
    new_mac = []
    for i in mac[:6]:  # FIXME: do we care about anything besides ethernet?
        next = "%.2x" % i
        new_mac.append(next)
    return ":".join(new_mac)


def int_to_4_bytes(num):
    x = []
    for i in range(4):
        x.insert(0, int((int(num) >> (8 * int(i))) & 0xFF))
    return x


def ip_to_list(address):
    return list(map(int, address.split(".")))


def bytes_to_ints(bytes):
    return list(map(ord, bytes))


def bytes_to_int(bytes):
    x = 0
    for i in bytes:
        x = (x << 8) | i
    return x


def get_packet_type(packet):
    _type = None
    if packet.IsOption("dhcp_message_type"):
        _type = bytes_to_int(packet.GetOption("dhcp_message_type"))
        if _type not in types:
            _type = False
    return _type


class Server:
    BUFLEN = 8192
    listen_bcast = "0.0.0.0"
    listen_port = 67
    bootpc_port = 68
    bootps_port = 67

    def __init__(self, dbq):
        self.__dbq = dbq
        # self.last_seen = {}
        self.seen = {}
        self.seen_cleanup = []
        self.dhcp_sockets = []
        self.dhcp_socket_info = {}
        self.dhcp_xmit_socket = {}  # initialize this in the sender

        self.sockets_initialized = False

        if not dhcp.server_listen:
            raise Exception(
                "Missing configuration option: openipam_config.dhcp.server_listen"
            )

    def _open_sockets(self):
        for s in dhcp.server_listen:
            if s["broadcast"]:
                bsocket_info = s.copy()
                bsocket_info["unicast"] = False
                bsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                bsocket.setsockopt(
                    socket.SOL_SOCKET, SO_BINDTODEVICE, bsocket_info["interface"]
                )
                bsocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                bsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                bsocket.bind((self.listen_bcast, self.listen_port))
                self.dhcp_sockets.append(bsocket)
                self.dhcp_socket_info[bsocket] = bsocket_info
            if s["unicast"]:
                usocket_info = s.copy()
                usocket_info["broadcast"] = False
                usocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                usocket.setsockopt(
                    socket.SOL_SOCKET, SO_BINDTODEVICE, usocket_info["interface"]
                )
                usocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                usocket.bind((usocket_info["address"], self.listen_port))
                self.dhcp_sockets.append(usocket)
                self.dhcp_socket_info[usocket] = usocket_info

        self.sockets_initialized = True

    def HandlePacket(self):
        if not self.sockets_initialized:
            self._open_sockets()
        rlist, wlist, xlist = select.select(self.dhcp_sockets, [], [])
        s = rlist[0]
        data, sender = s.recvfrom(self.BUFLEN)

        packet = dhcp_packet.DhcpPacket()
        try:
            packet.DecodePacket(data)
        except Exception as e:
            print_exception(e)
            b64_data = base64.b64encode(data)
            print("FAILED TO PARSE: %r: %r" % (e, b64_data))
            dhcp.get_logger().log(dhcp.logging.ERROR, "IGN/UNPARSABLE: %r" % b64_data)

            if raven_client:
                raven_client.captureMessage(
                    "Failed to parse invalid DHCP packet",
                    tags={"server": self.dhcp_socket_info[s]["address"]},
                    level=dhcp.logging.ERROR,
                    extra={
                        "b64_data": b64_data,
                        "server_ip_address": self.dhcp_socket_info[s]["address"],
                        "server_interface": self.dhcp_socket_info[s],
                        "t_name": "INVALID",
                        "recvd_from": sender,
                    },
                )
            return

        packet.set_sender(sender)
        packet.set_recv_interface(self.dhcp_socket_info[s])

        packet_type = get_packet_type(packet)
        if packet_type is False:
            log_packet(packet, prefix="IGN/INVALID TYPE:", raw=True)
        if not packet.IsDhcpPacket():
            log_packet(packet, prefix="IGN/INVALID PKT:", raw=True)
        self.QueuePacket(packet, packet_type)

    def SendPacket(self, packet, bootp=False, giaddr=None):
        """Encode and send the packet."""

        local_if = packet.get_recv_interface()

        local_addr = local_if.get("address", socket.INADDR_ANY)
        local_bcast = local_if.get("broadcast", False)
        s_key = (local_addr, local_bcast)

        if s_key not in self.dhcp_xmit_socket:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if local_if["broadcast"]:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((local_addr, self.listen_port))
            self.dhcp_xmit_socket[s_key] = s

            # sender = packet.get_sender()
        if giaddr is None:
            giaddr = ".".join(map(str, packet.GetOption("giaddr")))
        ciaddr = ".".join(map(str, packet.GetOption("ciaddr")))
        yiaddr = ".".join(map(str, packet.GetOption("yiaddr")))
        chaddr = decode_mac(packet.GetOption("chaddr"))

        if not bootp:
            server_id = list(
                map(int, packet.get_recv_interface()["address"].split("."))
            )
            packet.SetOption("server_identifier", server_id)  # DHCP server IP

            # See rfc1532 page 21
        if ciaddr != "0.0.0.0":
            log_packet(packet, prefix="SND/CIADDR:")
            dest = (ciaddr, self.bootpc_port)
        elif giaddr != "0.0.0.0":
            log_packet(packet, prefix="SND/GIADDR:")
            dest = (giaddr, self.bootps_port)
        elif yiaddr != "0.0.0.0":
            broadcast = packet.GetOption("flags")[0] >> 7

            if broadcast:
                log_packet(packet, prefix="SND/BCAST:")
                dest = ("255.255.255.255", self.bootpc_port)
            else:
                # FIXME: need to send this directly to chaddr :/
                # log_packet(packet, prefix='SND/CHADDR:')
                # dest = ( yiaddr, self.bootpc_port )
                try:
                    os.system(
                        "arp -H ether -i %s -s %s %s temp"
                        % (self.dhcp_iface, yiaddr, chaddr)
                    )
                    log_packet(packet, prefix="SND/ARPHACK:")
                    dest = (yiaddr, self.bootpc_port)
                except:
                    log_packet(packet, prefix="SND/HACK:")
                    dest = ("255.255.255.255", self.bootpc_port)
        else:
            log_packet(packet, prefix="IGN/SNDFAIL:", level=dhcp.logging.WARNING)
            raise Exception(
                "Cannot send packet without one of ciaddr, giaddr, or yiaddr."
            )

        self.dhcp_xmit_socket[s_key].sendto(packet.EncodePacket(), dest)

        if show_packets:
            print("------- Sending Packet ----------")
            # print sender
            print("local_if:", local_if)
            print("local_addr:", local_addr)
            packet.PrintHeaders()
            packet.PrintOptions()
            print("---------------------------------")

    def do_seen_cleanup(self, mac, min_timestamp):
        if mac not in self.seen:
            self.seen[mac] = []
        seen = self.seen[mac]

        # do some cleanup on our mac
        while seen and seen[0][0] < min_timestamp:
            del seen[0]

            # do a little bit of housekeeping while we're at it
        if self.seen_cleanup:
            cleanup_mac = self.seen_cleanup.pop()
            while (
                self.seen[cleanup_mac] and self.seen[cleanup_mac][0][0] < min_timestamp
            ):
                del self.seen[cleanup_mac][0]
            if not self.seen[cleanup_mac]:
                del self.seen[cleanup_mac]
        else:
            self.seen_cleanup = list(self.seen.keys())

        return seen

    def QueuePacket(self, packet, pkttype):
        mac = decode_mac(packet.GetOption("chaddr"))
        c_time = datetime.datetime.now()

        IGNORE_FOR = dhcp.init_delay_seconds  # seconds
        wait_time = packet.GetOption("secs")
        if wait_time < IGNORE_FOR:
            log_packet(packet, prefix="IGN/IGN_FOR:", level=dhcp.logging.INFO)
            print(
                "ignoring request type %s from mac %s because we are waiting for %d secs"
                % (pkttype, mac, IGNORE_FOR)
            )
            return

            # Minimum time between allowing a user to make the same kind of request
            # BETWEEN_REQUESTS = datetime.timedelta(days=0,minutes=0,seconds=10)
        TIME_PERIOD = datetime.timedelta(days=0, minutes=1, seconds=0)

        # types = { None:'bootp', 1:'discover', 2:'offer', 3:'request', 4:'decline', 5:'ack', 6:'nak', 7:'release', 8:'inform', }
        MESSAGE_TYPE_LIMIT = {
            None: 2,
            1: 6,
            3: 10,
            4: 12,
            7: 20,
            8: 16,
        }  # we are only counting serviced packets, regardless of type

        if pkttype in MESSAGE_TYPE_LIMIT:
            MAX_REQUESTS = MESSAGE_TYPE_LIMIT[pkttype]
        else:
            MAX_REQUESTS = 0

            # our_key = (mac, pkttype,)

            # Thanks to the morons at MS, we can't do this.
            # see http://support.microsoft.com/kb/835304 for more info
            # FIXME: find another way to prevent DoS.
            # if self.last_seen.has_key( our_key ):
            # 	time = self.last_seen[ our_key ]
            # 	if ( ( c_time - time ) < dhcp.between_requests ):
            # 		print "ignoring request type %s from mac %s because we saw a request at %s (current: %s)" % (pkttype, mac, str(time), str(c_time))
            # 		log_packet( packet, prefix='IGN/TIME:' )
            # 		return
            # 	else:
            # 		del self.last_seen[ our_key ]

        min_timestamp = c_time - TIME_PERIOD

        seen = self.do_seen_cleanup(mac, min_timestamp)

        if len(seen) > MAX_REQUESTS:
            log_packet(packet, prefix="IGN/LIMIT:", level=dhcp.logging.INFO)
            print(
                "ignoring request type %s from mac %s because we have seen %s requests in %s"
                % (pkttype, mac, len(seen), str(TIME_PERIOD))
            )
            return

        packet.retry_count = 0
        packet.last_retry = 0

        try:
            log_packet(packet, prefix="QUEUED:")
            self.__dbq.put_nowait((pkttype, packet))
        except Full as e:
            # The queue is full, try again later.
            log_packet(packet, prefix="IGN/FULL:", level=dhcp.logging.WARNING)
            print(
                "ignoring request type %s from mac %s because the queue is full ... be afraid"
                % (pkttype, mac)
            )
            return

            # If we get here, the packet should be in the queue, so we can
            # guarantee it will be seen by one of the workers.  Let's add
            # this to our list of things we don't want to respond to right
            # now.
            # self.last_seen[ our_key ] = ( c_time )
        seen.append((c_time, pkttype))


def parse_packet(packet):
    pkttype = get_packet_type(packet)
    if pkttype not in types:
        pkttype = False
    mac = decode_mac(packet.GetOption("chaddr"))
    xid = bytes_to_int(packet.GetOption("xid"))
    requested_options = packet.GetOption("parameter_request_list")

    if hasattr(dhcp, "force_options") and dhcp.force_options:
        requested_options.extend(dhcp.force_options)

    recvd_from = packet.get_sender()
    giaddr = ".".join(map(str, packet.GetOption("giaddr")))

    client_ip = ".".join(map(str, packet.GetOption("yiaddr")))
    if client_ip == "0.0.0.0":
        client_ip = ".".join(map(str, packet.GetOption("ciaddr")))
        if client_ip == "0.0.0.0":
            client_ip = bytes_to_ip(packet, "request_ip_address")
            if not client_ip:
                client_ip = packet.get_sender()[0]

    return (pkttype, mac, xid, client_ip, giaddr, recvd_from, requested_options)


types = {
    None: "bootp",
    1: "discover",
    2: "offer",
    3: "request",
    4: "decline",
    5: "ack",
    6: "nak",
    7: "release",
    8: "inform",
    False: "INVALID",
}


def log_packet(packet, prefix="", level=dhcp.logging.INFO, raw=False):
    # This should be called for every incoming or outgoing packet.
    pkttype, mac, xid, client, giaddr, recvd_from, req_opts = parse_packet(packet)

    t_name = types[pkttype] if pkttype in types else "INVALID"

    if giaddr != "0.0.0.0":
        client_foo = "%s via %s" % (client, giaddr)
    else:
        client_foo = str(client)

    if packet.IsOption("host_name"):
        host_name = packet.GetOption("host_name")
        client_foo = "%s [option 12: %s]" % (client_foo, "".join(map(chr, host_name)))

    raw_append = ""
    if raw:
        raw_data = (
            base64.b64encode(packet._raw_data) if packet._raw_data else packet._raw_data
        )
        raw_append = " RAW:%r" % raw_data

    dhcp.get_logger().log(
        level,
        "%-12s %-8s %s 0x%08x (%s)%s",
        prefix,
        t_name,
        mac,
        xid,
        client_foo,
        raw_append,
    )

    if raven_client and level >= raven_client_min_level or t_name == "decline":
        if "IGN" in prefix:
            if "LIMIT" in prefix:
                message = "request from %s ignored due to rate limiting" % mac
            elif "UNAVAIL" in prefix:
                message = "unable to find appropriate lease: giaddr=%s" % giaddr
            else:
                message = prefix[:-1]
        elif t_name == "decline":
            message = "dhcpdecline from host %s" % mac
        else:
            message = "%s %s from %s" % (prefix, t_name.upper(), mac)

        requested_ip = bytes_to_ip(packet, "request_ip_address")

        raven_client.captureMessage(
            message,
            tags={"server": packet.get_recv_interface()["address"]},
            level=level,
            extra={
                "server_ip_address": packet.get_recv_interface()["address"],
                "server_interface": packet.get_recv_interface(),
                "t_name": t_name,
                "mac": mac,
                "xid": xid,
                "client": client,
                "giaddr": giaddr,
                "requested_ip": requested_ip,
                "recvd_from": recvd_from,
            },
        )


def db_consumer(dbq, send_packet):
    class dhcp_packet_handler:
        # Order matters here.  We want type_map[1] == discover, etc
        def __init__(self, send_packet):
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
                tname, action = ("bootp", self.bootp_request)
            else:
                tname = types[type]
                action = self.type_map[type]

            if show_packets:
                print("############################# Recieved DHCP %s" % tname)
                packet.PrintHeaders()
                packet.PrintOptions()
                print("#############################")

            if action:
                action(packet)
            else:
                print("Don't know how to handle %s packet" % tname)

        def address_in_use(self, address):
            if True:
                return False
            if len(list(map(int, address.split(".")))) != 4:
                raise Exception("'%s' is not a valid IP address") % address
            cmd = ["/bin/ping", "-q", "-i0.1", "-c2", "-W1", address]
            retval = subprocess.call(cmd)
            return not retval

        def bootp_request(self, packet):
            mac = decode_mac(packet.GetOption("chaddr"))
            router = ".".join(map(str, packet.GetOption("giaddr")))
            ciaddr = ".".join(map(str, packet.GetOption("ciaddr")))
            opcode = packet.GetOption("op")[0]

            if router == "0.0.0.0":
                log_packet(packet, prefix="IGN/BOOTP:")
                return

                # self.__db.get_static( mac, gateway )
            return

        def dhcp_decline(self, packet):
            mac = decode_mac(packet.GetOption("chaddr"))
            requested_ip = bytes_to_ip(packet, "request_ip_address")

            if requested_ip and requested_ip != "0.0.0.0":
                dhcp.get_logger().log(
                    dhcp.logging.ERROR,
                    "%-12s Address in use: %s (from: %s)",
                    "ERR/DECL:",
                    requested_ip,
                    mac,
                )
                self.__db.mark_abandoned_lease(mac=mac, address=requested_ip)
            else:
                dhcp.get_logger().log(
                    dhcp.logging.ERROR,
                    "%-12s Address in use: (from: %s)",
                    "ERR/DECL2:",
                    mac,
                )
                # self.__db.mark_abandoned_lease( mac=mac )

        def dhcp_release(self, packet):
            mac = decode_mac(packet.GetOption("chaddr"))
            log_packet(packet, prefix="IGN/REL:")

        def assign_dhcp_options(self, options, requested, packet):
            opt_vals = {}
            for o in options:
                if o["value"] is None:  # unset this option, plz
                    packet.DeleteOption(DhcpRevOptions[o["oid"]])
                    if int(o["oid"]) in opt_vals:
                        del opt_vals[int(o["oid"])]
                else:
                    opt_vals[int(o["oid"])] = o["value"]

            preferred = []
            for oid in requested:
                if oid in DhcpRevOptions:
                    preferred.append(DhcpRevOptions[oid])

            packet.options_data.set_preferred_order(preferred)

            for i in list(opt_vals.keys()):
                packet.SetOption(DhcpRevOptions[i], bytes_to_ints(opt_vals[i]))
                print(
                    "Setting %s to '%s'"
                    % (DhcpRevOptions[i], bytes_to_ints(opt_vals[i]))
                )
                # Use  for next-server == siaddr
                if i == 11:
                    packet.SetOption("siaddr", bytes_to_ints(opt_vals[i]))
                    print(
                        "Setting next-server (siaddr) to '%s'"
                        % (bytes_to_ints(opt_vals[i]))
                    )
                    # Use tftp-server for next-server == sname
                if i == 66:
                    v = str(opt_vals[i])

                    v_padded = v + "\0" * (
                        64 - len(v)
                    )  # pydhcplib is too lame to do this for us
                    packet.SetOption("sname", bytes_to_ints(v_padded))
                    print("Setting sname to '%s'" % (bytes_to_ints(v)))
                    try:
                        host = self.__db.get_dns_records(tid=1, name=v)[0]
                        addr = list(map(int, host["ip_content"].split(".")))
                        packet.SetOption("siaddr", addr)
                        print("Setting next-server (siaddr) to '%s'" % (addr))
                    except:
                        pass
                        # Use tftp file name for bootfile
                if i == 67:
                    v = opt_vals[i]
                    v = v + "\0" * (
                        128 - len(v)
                    )  # pydhcplib is too lame to do this for us
                    packet.SetOption("file", bytes_to_ints(v))
                    print("Setting next-server to '%s'" % (bytes_to_ints(v)))
                    # print "Adding padding for lame fujitsu PXE foo"
                    # This doesn't work because pydhcplib sucks
                    # packet.SetOption("pad",'')

        def dhcp_inform(self, packet):
            mac = decode_mac(packet.GetOption("chaddr"))
            client_ip = ".".join(map(str, packet.GetOption("ciaddr")))
            requested_options = packet.GetOption("parameter_request_list")

            opt_vals = self.__db.retrieve_dhcp_options(
                mac=mac, address=client_ip, option_ids=requested_options
            )

            ack = DhcpPacket()
            ack.CreateDhcpAckPacketFrom(packet)

            # FIXME: check the RFC on 'hops'
            hops = packet.GetOption("hops")
            if hops:
                ack.SetOption("hops", hops)

            self.assign_dhcp_options(
                options=opt_vals, requested=requested_options, packet=ack
            )

            ack.DeleteOption("yiaddr")
            ack.DeleteOption("ip_address_lease_time")

            # send an ack
            self.SendPacket(ack)

        def dhcp_discover(self, packet):
            router = ".".join(map(str, packet.GetOption("giaddr")))
            mac = decode_mac(packet.GetOption("chaddr"))
            requested_ip = bytes_to_ip(packet, "request_ip_address")

            recv_if = packet.get_recv_interface()
            if router == "0.0.0.0":
                if recv_if["broadcast"]:
                    # hey, local DHCP traffic!
                    router = recv_if["address"]

            if not requested_ip:
                requested_ip = "0.0.0.0"

            lease = self.__db.make_dhcp_lease(
                mac,
                router,
                requested_ip,
                discover=True,
                server_address=recv_if["address"],
            )

            print("Got lease %s from database" % lease)

            while self.address_in_use(lease["address"]):
                print(
                    "Address %s in use, marking lease %s as abandoned"
                    % (lease["address"], lease)
                )
                dhcp.get_logger().log(
                    dhcp.logging.ERROR,
                    "%-12s Address in use: %(15)s (client: %s)",
                    "ERR/IN_USE:",
                    lease["address"],
                    mac,
                )
                self.__db.mark_abandoned_lease(address=lease["address"])
                lease = self.__db.make_dhcp_lease(
                    mac,
                    router,
                    requested_ip,
                    discover=True,
                    server_address=recv_if["address"],
                )
                print("Got new lease %s from database" % lease)

                # create an offer
            print("> creating offer")
            offer = DhcpPacket()
            offer.CreateDhcpOfferPacketFrom(packet)
            hops = packet.GetOption("hops")
            if hops:
                offer.SetOption("hops", hops)

                # fields
                # FIXME: get a free lease from the DB
                # we will need the function to return: the address, the gateway, the network/netmask/broadcast
                # FIXME: what about lease/renewal/rebinding_time, etc?
                # then offer it

                # Options to request from the DB (address/gateway are assumed)
            offer.SetOption("yiaddr", ip_to_list(lease["address"]))

            # options from DB
            print("setting lease time to %s seconds" % lease["lease_time"])
            offer.SetOption(
                "ip_address_lease_time", int_to_4_bytes(lease["lease_time"])
            )  # TEST
            # offer.SetOption("renewal_time_value",[0,0,0,60]) # TEST
            # offer.SetOption("rebinding_time_value",[0,0,0,105]) # TEST
            offer.SetOption("subnet_mask", ip_to_list(lease["netmask"]))
            offer.SetOption("broadcast_address", ip_to_list(lease["broadcast"]))  # TEST
            offer.SetOption("router", ip_to_list(lease["router"]))

            # offer.SetOption("hops",[1,]) # TEST: number of hops

            # make a list of requested DHCP options
            requested_options = packet.GetOption("parameter_request_list")
            print("requested_options: %s" % requested_options)

            if lease["hostname"] and DhcpOptions["host_name"] in requested_options:
                offer.SetOption("host_name", list(map(ord, lease["hostname"])))

                # get option/value pairs from database
            opt_vals = self.__db.retrieve_dhcp_options(
                mac=mac, address=requested_ip, option_ids=requested_options
            )
            print("opt_vals: %s" % str(opt_vals))

            self.assign_dhcp_options(
                options=opt_vals, requested=requested_options, packet=offer
            )

            # send an offer
            print("  > sending offer")
            self.SendPacket(offer)

            # def SendDhcpPacketTo(self, To, packet):
            # 	return self.dhcp_socket.sendto(packet.EncodePacket(),(To,self.emit_port))

        def dhcp_request(self, packet):
            # check to see if lease is still valid, if so: extend the lease and send an ACK
            router = ".".join(map(str, packet.GetOption("giaddr")))
            mac = decode_mac(packet.GetOption("chaddr"))
            ciaddr = ".".join(map(str, packet.GetOption("ciaddr")))

            recv_if = packet.get_recv_interface()
            if router == "0.0.0.0":
                if recv_if["broadcast"]:
                    # hey, local DHCP traffic!
                    router = recv_if["address"]

                    # FIXME: If ciaddr is set, we should use a unicast message to the client
            requested_ip = bytes_to_ip(packet, "request_ip_address")

            if not requested_ip:
                requested_ip = ciaddr
                if not requested_ip:
                    raise Exception("This really needs fixed...")

            if router == "0.0.0.0" and recv_if["unicast"]:
                # this was a unicast packet, I hope...
                router = requested_ip

            giaddr = ".".join(map(str, packet.GetOption("giaddr")))

            print("mac: %s, requested address: %s" % (mac, requested_ip))
            # make sure a valid lease exists

            try:
                lease = self.__db.make_dhcp_lease(
                    mac,
                    router,
                    requested_ip,
                    discover=False,
                    server_address=recv_if["address"],
                )
            except error.InvalidIPAddress as e:
                lease = {"address": None, "error": "address not allowed for client"}
            print("got lease: %s" % str(lease))
            if lease["address"] != requested_ip:
                # FIXME: Send a DHCP NAK if authoritative
                print(
                    "Lease appears invalid... client wants %s, but db gave us %s -- sending NAK"
                    % (requested_ip, lease["address"])
                )
                nak = DhcpPacket()
                # Why use 'NAK' when we can say 'NACK' (which means nothing to me)
                nak.CreateDhcpNackPacketFrom(packet)
                hops = packet.GetOption("hops")
                if hops:
                    nak.SetOption("hops", hops)
                self.SendPacket(nak, giaddr=router)
                return

            ack = DhcpPacket()
            ack.CreateDhcpAckPacketFrom(packet)
            # make a list of requested DHCP options
            requested_options = packet.GetOption("parameter_request_list")
            print("requested_options: %s" % requested_options)

            if lease["hostname"] and DhcpOptions["host_name"] in requested_options:
                ack.SetOption("host_name", list(map(ord, lease["hostname"])))

                # get option/value pairs from database
            opt_vals = self.__db.retrieve_dhcp_options(
                mac=mac, address=requested_ip, option_ids=requested_options
            )
            print("opt_vals: %s" % str(opt_vals))

            print("Got lease %s from database" % lease)
            # set them on the packet
            # Options to request from the DB (address/gateway are assumed)
            ack.SetOption("yiaddr", ip_to_list(lease["address"]))

            hops = packet.GetOption("hops")
            if hops:
                ack.SetOption("hops", hops)
            ack.SetOption(
                "ip_address_lease_time", int_to_4_bytes(lease["lease_time"])
            )  # TEST
            ack.SetOption("subnet_mask", ip_to_list(lease["netmask"]))
            ack.SetOption("broadcast_address", ip_to_list(lease["broadcast"]))  # TEST
            ack.SetOption("router", ip_to_list(lease["router"]))

            self.assign_dhcp_options(
                options=opt_vals, requested=requested_options, packet=ack
            )

            # send an ack
            print("  > sending ack")
            self.SendPacket(ack)

            print(
                "#############################################################################"
            )

    dhcp_handler = dhcp_packet_handler(send_packet)

    # my_logfile = '/var/log/dhcp/dhcp_server_worker.%s' % os.getpid()
    # logfile = open( my_logfile, 'a' )
    # logfile.write('Starting worker process.\n')
    # os.dup2( logfile.fileno(), sys.stdout.fileno() )

    # FIXME: don't create sqlalchemy db connection foo at global module level so we don't have to hack like this
    from openipam.backend.db import interface

    REQUEUE_DELAY = 0.2  # seconds
    REQUEUE_MAX = 5  # number of attempts

    def requeue(p_type, packet):
        success = False
        try:
            dbq.put_nowait((p_type, packet))
            success = True
        except Full as e:
            print("Queue full, not requeueing")
            log_packet(packet, prefix="IGN/REQFAIL:", level=dhcp.logging.ERROR)
        return success

    while True:
        # FIXME: for production, this should be in a try/except block
        pkttype = None
        pkt = None
        try:
            pkttype, pkt = dbq.get()
            # Handle request
            try:
                if (time.time() - pkt.last_retry) > REQUEUE_DELAY:
                    dhcp_handler.handle_packet(pkt, type=pkttype)
                else:
                    requeue(pkttype, pkt)
            except interface.DHCPRetryError as e:
                pkt.retry_count += 1

                if pkt.retry_count <= REQUEUE_MAX:
                    pkt.last_retry = time.time()
                    # if the queue is full, we probably want to ignore this packet anyway
                    print("re-queueing packet for retry: %r" % e)
                    if requeue(pkttype, pkt):
                        log_packet(
                            pkt, prefix="IGN/REQUEUE:", level=dhcp.logging.WARNING
                        )
                else:
                    print("dropping packet after too many retries: %r" % e)
                    log_packet(pkt, prefix="IGN/TOOMANY:", level=dhcp.logging.ERROR)

        except error.NotFound as e:
            # print_exception( e, traceback=False )
            print("sorry, no lease found")
            log_packet(pkt, prefix="IGN/UNAVAIL:", level=dhcp.logging.ERROR)
            print(str(e))
        except Exception as e:
            print_exception(e)
            if raven_client:
                try:
                    pkttype, mac, xid, client, giaddr, recvd_from, req_opts = (
                        None,
                    ) * 7
                    if pkt is not None:
                        pkttype, mac, xid, client, giaddr, recvd_from, req_opts = parse_packet(
                            pkt
                        )
                    raven_client.captureException(
                        data={
                            "extra": {
                                "mac": mac,
                                "pkttype": pkttype,
                                "xid": xid,
                                "client": client,
                                "giaddr": giaddr,
                                "recvd_from": recvd_from,
                                "req_opts": req_opts,
                                "dhcp_packet": pkt,
                            }
                        }
                    )
                except Exception as e:
                    print("failed to send exception to raven")
                    print_exception(e)

                # logfile.close()


def print_exception(exc, traceback=True):
    import traceback

    # FIXME: Do some syslogging here
    if traceback:
        # traceback_file = '/var/log/dhcp/tracebacks'
        traceback_file = dhcp.traceback_file
        tb_file = open(traceback_file, "a")
        tb_file.write("\n----- start %s -----\n" % datetime.datetime.now())
        traceback.print_exc(file=tb_file)
        tb_file.write(str(exc))
        tb_file.write("\n----- end -----\n")
        tb_file.close()
        traceback.print_exc()
    print(str(exc))
