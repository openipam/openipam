#!/usr/bin/env python3

from openipam import dhcp_server
from openipam.utilities import daemon
import multiprocessing as processing
import atexit
import ctypes

from optparse import OptionParser

# parse command line options
parser = OptionParser()
parser.add_option(
    "-v",
    "--version",
    action="store_true",
    dest="version",
    help="Print the version and exit.",
)
parser.add_option(
    "-d",
    "--daemon",
    action="store_true",
    dest="daemon",
    help="Start program as a daemon.",
    default=False,
)
parser.add_option(
    "-s",
    "--signals",
    action="store_true",
    dest="signals",
    help="Use signal processing code.",
)

parser.add_option(
    "-p",
    "--pidfile",
    action="store",
    type="string",
    dest="pidfile",
    help="Use the given filename to store the PID of the server.",
    default="/var/run/openipam/openipam_dhcpd.pid",
)

(options, args) = parser.parse_args()


def consumer(*args, **kwargs):
    libc = ctypes.CDLL("libc.so.6")
    # 1 = PR_SET_PDEATHSIG, 15 = TERM
    # Should send a TERM to this child when the parent dies
    libc.prctl(1, 15)
    dhcp_server.db_consumer(*args, **kwargs)


def start():
    NUM_WORKERS = 10
    db_requests = processing.Queue(NUM_WORKERS)

    server = dhcp_server.Server(dbq=db_requests)

    db_pool = processing.Pool(
        processes=NUM_WORKERS,
        initializer=consumer,
        initargs=(db_requests, server.SendPacket),
    )
    atexit.register(db_pool.terminate)
    atexit.register(db_pool.join)

    while True:
        server.HandlePacket()


if __name__ == "__main__":
    # FIXME: need command-line arguments
    pidfile = "/var/run/openipam/openipam_dhcpd"
    if options.daemon:
        daemon.daemonize(start, options.pidfile)
    else:
        start()
