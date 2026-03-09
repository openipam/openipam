#!/usr/bin/python
import multiprocessing as processing
from openipam import dhcp_server
from openipam.config import dhcp
import random
import datetime
from sqlalchemy import select

from queue import Empty


def get_rand_item(lst):
    # Standard Row objects support attribute access
    rp = lst[random.randrange(0, len(lst))]
    item = {"address": None}

    # We use getattr because it's safer when working with a dynamic list of keys
    for i in ["mac", "address", "gateway"]:
        if hasattr(rp, i):
            item[i] = getattr(rp, i)
    return item


class PacketGenerator:
    def __init__(self, sendq):
        self.sendq = sendq
        self.recvq = processing.Queue()
        self.packets_sent = 0

    def connect(self):
        from openipam.backend.db import obj

        self.obj = obj
        from openipam.backend.db import interface

        self.__db = interface.DBBackendInterface()
        self.statics = self.__get_statics()
        self.dynamics = self.__get_dynamics()

        self.dynamic_macs = [d.mac for d in self.dynamics]

        self.leased_dynamics = []
        self.leased_unregistered = []
        self.gateways = self.get_gateways()

    def __get_statics(self):
        statics_q = (
            select(self.obj.addresses, self.obj.networks.c.gateway)
            .select_from(
                self.obj.addresses.join(
                    self.obj.networks,
                    self.obj.addresses.c.address.op("<<")(self.obj.networks.c.network),
                )
            )
            .where(self.obj.addresses.c.mac.is_not(None))
        )
        return self.__db._execute(statics_q)

    def __get_dynamics(self):
        dynamics_q = select(self.obj.hosts_to_pools.c.mac)
        return self.__db._execute(dynamics_q)

    def get_random_mac(self):
        return f"aa:aa:aa:{random.randrange(0, 256):02x}:{random.randrange(0, 256):02x}:{random.randrange(0, 256):02x}"

    def get_gateways(self, local_gateways_only=False):
        gateways_q = select(self.obj.networks.c.gateway)
        if local_gateways_only:
            gateways_q = gateways_q.where(
                self.obj.networks.c.gateway.op("<<")(dhcp.server_subnet)
            )
        return self.__db._execute(gateways_q)

    def send_packet(self, packet, send_to=None, bootp=None):
        self.recvq.put((packet, send_to, bootp))
        self.packets_sent += 1

    def handle_result_packet(self, packet, send_to, bootp):
        mac = dhcp_server.decode_mac(packet.GetOption("chaddr"))
        address = ".".join(map(str, packet.GetOption("yiaddr")))
        gateway = ".".join(map(str, packet.GetOption("giaddr")))
        data = {"mac": mac, "address": address, "gateway": gateway}
        if mac[:9] == "aa:aa:aa:":
            self.leased_unregistered.append(data)
        if mac in self.dynamic_macs:
            self.leased_unregistered.append(data)

    def GetNextDhcpPacket(self):
        static = dynamic = unregistered = False
        rnd = random.random()
        if rnd < 0.1:
            static = True
        elif rnd < 0.8:
            dynamic = True
        else:
            unregistered = True
        try:
            pkt = self.recvq.get_nowait()
            while pkt:
                packet, send_to, bootp = pkt
                self.handle_result_packet(packet, send_to, bootp)
                pkt = self.recvq.get_nowait()
        except Empty:
            pass

        discover = (random.random() < 0.25) or (len(self.leased_dynamics) < 100)
        bound = random.random() < 0.75

        selected_gateway = get_rand_item(self.gateways)["gateway"]

        if static:
            info = get_rand_item(self.statics)
        elif dynamic and discover:
            info = get_rand_item(self.dynamics)
        elif dynamic:
            info = get_rand_item(self.leased_dynamics)
        elif unregistered and discover:
            info = {"mac": self.get_random_mac(), "address": None}
        else:
            info = get_rand_item(self.leased_unregistered)

        address = info["address"]
        mac = info["mac"]

        if not address:
            address = "10.0.0.1"

        msg_type, packet = make_dhcp_packet(
            discover=discover, requested=address, bound=bound, mac=mac, gateway=selected_gateway
        )
        self.sendq.put((msg_type, packet))


def hex2int(s):
    return int(s.strip(), 16)


def breakmac(m):
    mac = list(map(hex2int, m.split(":")))
    for i in range(16 - len(mac)):
        mac.append(0)
    return mac


def make_dhcp_packet(mac, requested, gateway, discover=False, bound=True):
    packet = dhcp_server.dhcp_packet.DhcpPacket()
    mock_interface = {
        "address": "192.168.56.3",
        "broadcast": "192.168.56.255",
        "interface": "eth0",
        "unicast": True,
    }
    packet.retry_count = 0
    packet.set_recv_interface(mock_interface)
    if discover or not bound:
        msg_type = 1
        packet.SetOption("request_ip_address", requested.split("."))
    else:
        msg_type = 3
        packet.SetOption("ciaddr", requested.split("."))

    packet.SetOption("dhcp_message_type", [msg_type])
    packet.SetOption("htype", [1])
    packet.SetOption("chaddr", breakmac(mac))
    packet.SetOption("xid", [0, 1, 2, 3])
    packet.SetOption("giaddr", gateway.split("."))
    packet.SetOption("op", [1])
    packet.SetOption("hlen", [6])
    packet.SetOption(
        "parameter_request_list",
        [1, 3, 6, 15, 31, 33, 119, 95, 252, 44, 46, 47, 42, 28],
    )
    return msg_type, packet


if __name__ == "__main__":
    NUM_WORKERS = 10
    db_requests = processing.Queue(NUM_WORKERS)

    server = PacketGenerator(db_requests)

    db_pool = processing.Pool(
        processes=NUM_WORKERS,
        initializer=dhcp_server.db_consumer,
        initargs=(db_requests, server.send_packet),
    )

    server.connect()

    nreq = 2000
    start = datetime.datetime.now()
    print("starting at %s" % start)
    for i in range(nreq):
        server.GetNextDhcpPacket()
    end = datetime.datetime.now()
    print("ending at %s" % end)
    duration = end - start
    print(f"requests: {nreq} duration: {duration}")
