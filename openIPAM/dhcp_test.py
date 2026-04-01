#!/usr/bin/python
import multiprocessing as mp
from openipam import dhcp_server
from openipam.dhcp_server import dhcp_packet
import random
import datetime
import time

from queue import Empty

# This test isn't super great because:
# 1. It isn't deterministic (okay for a load test)
# 2. Doesn't report any aggregate statistics (less okay for a load test)
# 3. Doesn't prioritize fetching macs with a lease under the given network,
#    leading to most of the mock DHCP requests not having a valid lease
#    and erroring out.
# It could be useful in the future but for now it isn't worth the effort of updating too much


def get_rand_item(lst):
    rp = lst[random.randrange(0, len(lst))]
    item = {"address": None}
    for i in ["mac", "address", "gateway"]:
        if i in rp:
            item[i] = rp[i]
    return item


class PacketGenerator(object):
    def __init__(self, sendq):
        # ie. send to backend
        self.sendq = sendq
        # ie. recieve from backend
        self.recvq = mp.Queue()
        self.packets_sent = 0

    def connect(self):
        from openipam.backend.db import obj

        self.obj = obj
        from openipam.backend.db import interface

        self.__db = interface.DBBackendInterface()
        self.statics = self.__get_statics()
        self.dynamics = self.__get_dynamics()
        self.dynamic_macs = []
        for d in self.dynamics:
            self.dynamic_macs.append(d["mac"])
        self.leased_dynamics = []
        self.leased_unregistered = []
        self.gateways = self.get_gateways()

    def __get_statics(self):
        statics_q = self.obj.select(
            [self.obj.addresses, self.obj.networks.c.gateway],
            from_obj=self.obj.addresses.join(
                self.obj.networks,
                self.obj.addresses.c.address.op("<<")(self.obj.networks.c.network),
            ),
        )
        statics_q = statics_q.where(self.obj.addresses.c.mac != None).limit(200)  # noqa: E711
        return self.__db._execute(statics_q)

    def __get_dynamics(self):
        dynamics_q = (
            self.obj.select([self.obj.hosts_to_pools.c.mac])
            .where(self.obj.addresses.c.mac != None)  # noqa: E711
            .limit(200)
        )
        return self.__db._execute(dynamics_q)

    def get_random_mac(self):
        return "aa:aa:aa:%2x:%2x:%2x" % (
            random.randrange(0, 256),
            random.randrange(0, 256),
            random.randrange(0, 256),
        )

    def get_gateways(self):
        gateways_q = self.obj.select([self.obj.networks.c.gateway])
        gateways_q = gateways_q.where(
            self.obj.networks.c.gateway.op("<<")("172.17.111.0/16")
        )
        return self.__db._execute(gateways_q)

    def send_packet(self, packet, send_to=None, bootp=None):
        # This will only be called by our worker processes, so it doesn't
        # have access to any memory in this process.  Only talk to recvq.
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
        # First, decide which kind of packet to 'handle': [discover,request], [static,
        # dynamic, ...], [valid, invalid]
        # static/dynamic/unregistered
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

        if static:
            info = get_rand_item(self.statics)
            info["gateway"] = info["address"]  # this shouldn't change performance
        elif dynamic and discover:
            info = get_rand_item(self.dynamics)
            info["gateway"] = get_rand_item(self.gateways)["gateway"]
        elif dynamic:
            info = get_rand_item(self.leased_dynamics)
        elif unregistered and discover:
            info = {"mac": self.get_random_mac(), "address": None}
            info["gateway"] = get_rand_item(self.gateways)["gateway"]
        else:
            info = get_rand_item(self.leased_unregistered)

        address = info["address"]
        mac = info["mac"]
        gateway = info["gateway"]

        if not address:
            address = "10.0.0.1"

        type, packet = make_dhcp_packet(
            discover=discover, requested=address, bound=bound, mac=mac, gateway=gateway
        )
        self.sendq.put((type, packet))


def hex2int(s):
    return int(s.strip(), 16)


def breakmac(m):
    mac = list(map(hex2int, m.split(":")))
    for i in range(16 - len(mac)):
        mac.append(0)
    return mac


def make_dhcp_packet(mac, requested, gateway, discover=False, bound=True):
    packet = dhcp_packet.DhcpPacket()
    if discover or not bound:
        type = 1
        packet.SetOption("request_ip_address", requested.split("."))
    else:
        type = 3
        packet.SetOption("ciaddr", requested.split("."))
    mock_if = {
        "address": "172.17.111.23",
        "broadcast": "172.17.111.255",
        "interface": "eth0",
        "unicast": True,
    }
    packet.retry_count = 0
    packet.set_recv_interface(mock_if)

    packet.SetOption("dhcp_message_type", [type])

    packet.SetOption("htype", [1])  # ethernet
    packet.SetOption("chaddr", breakmac(mac))
    packet.SetOption("xid", [0, 1, 2, 3])  # currently ignored by the server
    # packet.SetOption("flags",) # doesn't matter, since we don't look at it
    packet.SetOption("giaddr", gateway.split("."))
    # packet.SetOption("ip_address_lease_time", ) # also ignored

    packet.SetOption("op", [1])
    packet.SetOption("hlen", [6])

    packet.SetOption(
        "parameter_request_list",
        [1, 3, 6, 15, 31, 33, 119, 95, 252, 44, 46, 47, 42, 28],
    )
    packet.last_retry = datetime.datetime.now().timestamp()
    # packet.SetOption("client_identifier") # ignored
    # packet.SetOption("maximum_message_size") # ignored
    return type, packet


if __name__ == "__main__":
    print("running load test")
    NUM_WORKERS = 10
    db_requests = mp.Queue()
    result_q = mp.Queue()

    server = PacketGenerator(db_requests)
    server.recvq = result_q

    # IMPORTANT: don't share PacketGenerator instance across processes
    def send_packet(packet, send_to=None, bootp=None):
        result_q.put((packet, send_to, bootp))

    workers = []
    for _ in range(NUM_WORKERS):
        p = mp.Process(
            target=dhcp_server.db_consumer,
            args=(db_requests, send_packet),
        )
        p.start()
        workers.append(p)

    
    server.connect()

    nreq = 2000
    start = datetime.datetime.now()
    print("starting at %s" % start)
    for i in range(nreq):
        print("get next packet")
        # while True:
        # Sleep an appropriate amount of time to get the appropriate number of packets
        # per second
        # Create a packet to put in our queue

        # Now, put it there
        server.GetNextDhcpPacket()

    # Can't gracefully shutdown processes, so sleep for a bit to let them process and manually terminate processes
    time.sleep(4)
    for p in workers:
        p.terminate()
        p.join()
    time.sleep(3)

    end = datetime.datetime.now()
    print("ending at %s" % end)
    duration = end - start
    print("requests: %s duration: %s" % (nreq, duration))
