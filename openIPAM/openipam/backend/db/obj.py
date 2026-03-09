from sqlalchemy import create_engine, MetaData, Table
from sqlalchemy.sql import select, and_, Subquery

from openipam.config import backend

_user = backend.db_username

if not _user:
    _user = ""

_pass = backend.db_password
if not _pass:
    _pass = ""

_host = backend.db_host
_db = backend.db_database

db_str = "{}://{}{}{}{}{}/{}".format(
    "postgresql",
    _user,
    (_pass and ":" or ""),
    _pass,
    (_user and "@" or ""),
    _host,
    _db,
)

# FIXME: add connect_args={'sslmode':True} and make it work
# sslmode must be a string (see postgres docs for more info)
engine = create_engine(
    db_str,
    echo=backend.db_show_sql,
    pool_size=15,
    max_overflow=20,
    connect_args=backend.db_connect_args,
)

meta = MetaData()
meta.bind = engine

permissions = Table("permissions", meta, autoload_with=engine)
auth_sources = Table("auth_sources", meta, autoload_with=engine)
users = Table("users", meta, autoload_with=engine)
groups = Table("groups", meta, autoload_with=engine)
users_to_groups = Table("users_to_groups", meta, autoload_with=engine)
internal_auth = Table("internal_auth", meta, autoload_with=engine)
dhcp_groups = Table("dhcp_groups", meta, autoload_with=engine)
dhcp_options = Table("dhcp_options", meta, autoload_with=engine)
dhcp_options_to_dhcp_groups = Table("dhcp_options_to_dhcp_groups", meta, autoload_with=engine)
hosts = Table("hosts", meta, autoload_with=engine)
hosts_to_groups = Table("hosts_to_groups", meta, autoload_with=engine)
pools = Table("pools", meta, autoload_with=engine)
pools_to_groups = Table("pools_to_groups", meta, autoload_with=engine)
hosts_to_pools = Table("hosts_to_pools", meta, autoload_with=engine)
addresses = Table("addresses", meta, autoload_with=engine)
leases = Table("leases", meta, autoload_with=engine)
attributes = Table("attributes", meta, autoload_with=engine)
structured_attribute_values = Table("structured_attribute_values", meta, autoload_with=engine)
structured_attributes_to_hosts = Table(
    "structured_attributes_to_hosts", meta, autoload_with=engine
)
freeform_attributes_to_hosts = Table(
    "freeform_attributes_to_hosts", meta, autoload_with=engine
)
attributes_to_hosts = Table("attributes_to_hosts", meta, autoload_with=engine)
domains = Table("domains", meta, autoload_with=engine)
domains_to_groups = Table("domains_to_groups", meta, autoload_with=engine)
dns_types = Table("dns_types", meta, autoload_with=engine)
dns_views = Table("dns_views", meta, autoload_with=engine)
dns_records = Table("dns_records", meta, autoload_with=engine)
dhcp_dns_records = Table("dhcp_dns_records", meta, autoload_with=engine)
pdns_zone_xfer = Table("pdns_zone_xfer", meta, autoload_with=engine)
supermasters = Table("supermasters", meta, autoload_with=engine)
networks = Table("networks", meta, autoload_with=engine)
networks_to_groups = Table("networks_to_groups", meta, autoload_with=engine)
shared_networks = Table("shared_networks", meta, autoload_with=engine)
guest_tickets = Table("guest_tickets", meta, autoload_with=engine)
expiration_types = Table("expiration_types", meta, autoload_with=engine)
notifications = Table("notifications", meta, autoload_with=engine)
notifications_to_hosts = Table("notifications_to_hosts", meta, autoload_with=engine)
disabled = Table("disabled", meta, autoload_with=engine)

if backend.enable_gul:
    gul_recent_arp_byaddress = Table("gul_recent_arp_byaddress", meta, autoload_with=engine)
    gul_recent_arp_bymac = Table("gul_recent_arp_bymac", meta, autoload_with=engine)


def perm_query(
    uid,
    min_perms,
    hosts=False,
    networks=False,
    domains=False,
    gid=None,
    pools=False,
    required_perms=None,
    do_subquery=True,
    andwhere=None,
):
    """Return an SQLAlchemy select object containing the users groups and
    permissions in each of the specified tables.
    @param uid: The user's id (ie. "users.id")
    @param min_perms: The user's minimum permissions
    @param hosts: Whether to include hosts_to_groups information
    @param networks: Whether to include networks_to_groups information
    @param domains: Whether to include domains_to_groups information
    @param gid: If specified, query will be filtered down to this group ID
    @param required_perms: The permissions we are looking for
    @param do_subquery: Do a subquery() instead of a select
    @param andwhere: this is a hack to allow us to add stuff to the where clause
    @return: sqlalchemy query object with uid, gid, and optionally mac,
        host_perms, nid, network_perms, did, domain_perms
    """
    columns = [
        users_to_groups.c.uid,
        users_to_groups.c.gid,
        users_to_groups.c.permissions,
    ]
    fromclause = users_to_groups

    # FIXME: do something about required_perms in the where clause

    if hosts:
        columns.extend([hosts_to_groups.c.mac])
        fromclause = fromclause.outerjoin(
            hosts_to_groups, users_to_groups.c.gid == hosts_to_groups.c.gid
        )
    if networks:
        columns.extend([networks_to_groups.c.nid])
        fromclause = fromclause.outerjoin(
            networks_to_groups, users_to_groups.c.gid == networks_to_groups.c.gid
        )
    if domains:
        columns.extend([domains_to_groups.c.did])
        fromclause = fromclause.outerjoin(
            domains_to_groups, users_to_groups.c.gid == domains_to_groups.c.gid
        )
    if pools:
        columns.extend([pools_to_groups.c.pool])
        fromclause = fromclause.outerjoin(
            pools_to_groups, users_to_groups.c.gid == pools_to_groups.c.gid
        )

    whereclause = users_to_groups.c.uid == uid

    # If we need to require a certain level of permissions, and my min_perms don't
    # satisify that, then ask the DB:
    if required_perms and (required_perms & min_perms != required_perms):
        if not hosts:
            whereclause = and_(
                whereclause,
                users_to_groups.c.permissions.op("|")(str(min_perms)).op("&")(
                    str(required_perms)
                )
                == str(required_perms),
            )
        else:
            whereclause = and_(
                whereclause,
                users_to_groups.c.permissions.op("|")(
                    users_to_groups.c.host_permissions
                )
                .op("|")(str(min_perms))
                .op("&")(str(required_perms))
                == str(required_perms),
            )

    if gid:
        whereclause = and_(whereclause, users_to_groups.c.gid == gid)

    if andwhere is not None:
        whereclause = and_(whereclause, andwhere)

    if do_subquery:
        query = subquery("perms", columns, whereclause, from_obj=fromclause)
    else:
        query = select(columns, whereclause, from_obj=fromclause)

    return query
