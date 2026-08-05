# The default DHCP lease time for all statically assigned addresses. Dynamic
# lease times are configured on the pool.
static_lease_time = 86400

# The IP address of this server
server_listen = [
    {"address": "192.168.0.1", "interface": "eth0", "broadcast": True, "unicast": True}
]

server_subnet = "192.168.0.0/16"

# DHCP options that should always be returned if they are defined
force_options = [66, 67]
