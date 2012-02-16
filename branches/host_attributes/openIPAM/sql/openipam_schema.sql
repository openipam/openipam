CREATE TABLE permissions (
	id				BIT(8) PRIMARY KEY,
	name			text,
	description		text
);

COPY permissions ( id, name, description ) FROM stdin;
00000000	NONE	No permissions
00000001	ADMIN	Edit permissions
00000010	ADD	Write new records
00000100	READ	Read records
00001000	DELETE	Delete records
00000110	READ_ADD	Read and add (but not modify) records
00001110	MODIFY	Read and modify (and add and delete) records
00001111	OWNER	The owner gets to do a lot of things...
00010000	SECURITY	Special permission for disabling hosts
11111111	DEITY	All permissions
\.

--00010000	FUTURE	Future growth (not used)
--00100000	FUTURE	Future growth (not used)
--01000000	FUTURE	Future growth (not used)
--10000000	FUTURE	Future growth (not used)

CREATE TABLE auth_sources (
	id				INTEGER PRIMARY KEY,
	name			varchar UNIQUE
	-- Reference the authentication plugin here?
);

-- If you modify this dataset, change backend.auth.sources as well
COPY auth_sources ( id, name ) FROM stdin;
1	INTERNAL
2	LDAP
\.

-- If you modify this table, make sure that everything in
-- backend.db.interfaces DBBaseInterface __init__ still works
CREATE TABLE users (
	id				SERIAL PRIMARY KEY,
	username		varchar(50) NOT NULL UNIQUE,
	source			integer NOT NULL DEFAULT 1 REFERENCES auth_sources(id) ON DELETE RESTRICT,
	min_permissions	BIT(8) NOT NULL DEFAULT B'00000000' REFERENCES permissions(id) ON DELETE RESTRICT
);

-- FIXME: Trim this list down, we may not need the dhcp user 
INSERT INTO users (username, source, min_permissions) VALUES ('admin', 1, B'11111111');
INSERT INTO users (username, source, min_permissions) VALUES ('dhcp', 1, B'11111111');
INSERT INTO users (username, source, min_permissions) VALUES ('auth', 1, B'11111111');
INSERT INTO users (username, source, min_permissions) VALUES ('guest', 1, B'00000100');

CREATE TABLE groups(
	-- These groups are used for user groups, host groups, permissions, etc.
	-- Think of them as a central linking point for everything
	id				SERIAL PRIMARY KEY,
	name			text UNIQUE,
	description		text,
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT
);

INSERT INTO groups (name, description) VALUES ('default', 'The default group for all dynamic domains and member objects. Do not change.');
INSERT INTO groups (name, description) VALUES ('guests', 'The default group for all guest domains and member objects. Do not change.');
INSERT INTO groups (name, description) VALUES ('service', 'A service group for special permissions.');
INSERT INTO groups (name, description) VALUES ('user_admin', 'Default group for this user');
INSERT INTO groups (name, description) VALUES ('user_import', 'Default group for this user');
INSERT INTO groups (name, description) VALUES ('user_pdns', 'Default group for this user');
INSERT INTO groups (name, description) VALUES ('user_dhcp', 'Default group for this user');

CREATE TABLE users_to_groups(
	id				SERIAL PRIMARY KEY,
	uid				integer NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
	gid				integer NOT NULL REFERENCES groups(id) ON DELETE CASCADE ON UPDATE CASCADE,
	permissions		BIT(8)  NOT NULL REFERENCES permissions(id) ON DELETE RESTRICT,
	host_permissions BIT(8) NOT NULL REFERENCES permissions(id) ON DELETE RESTRICT,
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	UNIQUE (uid, gid)
);

CREATE INDEX users_to_groups_uid_gid_index ON users_to_groups( uid, gid);

CREATE TABLE internal_auth(
	-- Use for users not in LDAP
	id				integer PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
	hash			varchar NOT NULL,
	name			varchar, -- Users full name
	email			varchar, -- User's email address
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT
);

CREATE TABLE dhcp_groups (
	-- Groups used to determine which DHCP options should apply to a given host
	id				SERIAL PRIMARY KEY,
	name			varchar(255),
	description		text,
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT
);

CREATE TABLE shared_networks (
	id				SERIAL PRIMARY KEY,
	name			varchar(255) UNIQUE NOT NULL,
	description		text,
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT
);

INSERT INTO dhcp_groups (name, description, changed_by) VALUES ( 'global', 'dhcp options applied to all hosts unless overridden by more specific options', 1);
INSERT INTO dhcp_groups (name, description, changed_by) VALUES ( 'routable', 'routed, registered addresses', 1);
INSERT INTO dhcp_groups (name, description, changed_by) VALUES ( 'non-routable', 'non-routed, registered addresses', 1);
INSERT INTO dhcp_groups (name, description, changed_by) VALUES ( 'restricted', 'not registered: only allow access for updates or registration', 1);

CREATE TABLE dhcp_options (
	id				integer PRIMARY KEY,
	size			varchar(10),
	name			varchar(255) UNIQUE,
	-- the option, as expected in dhcpd.conf
	option			varchar(255) UNIQUE,
	comment			text
);

-- Removed lease time from the DHCP options because we set this globally in the config
-- for statics and on the pool for dynamics.

COPY dhcp_options ( id, size, name, option, comment ) FROM stdin;
0	1	Pad	pad	Pad.
1	4	Subnet Mask	subnet-mask	Subnet Mask.
2	4	Time Offset 	time-offset-	Time Offset (deprecated).
3	4+	Router	router	Router.
4	4+	Time Server	time-server	Time Server.
5	4+	Name Server	name-server	Name Server.
6	4+	Domain Name Server	domain-name-server	Domain Name Server.
7	4+	Log Server	log-server	Log Server.
8	4+	Quote Server	quote-server	Quote Server.
9	4+	LPR Server	lpr-server	LPR Server.
10	4+	Impress Server	impress-server	Impress Server.
11	4+	Resource Location Server	resource-location-server	Resource Location Server.
12	1+	Host Name	host-name	Host Name.
13	2	Boot File Size	boot-file-size	Boot File Size.
14	1+	Merit Dump File	merit-dump-file	Merit Dump File.
15	1+	Domain Name	domain-name	Domain Name.
16	4	Swap Server	swap-server	Swap Server.
17	1+	Root Path	root-path	Root Path.
18	1+	Extensions Path	extensions-path	Extensions Path.
19	1	IP Forwarding enable	ip-forwarding-enable	IP Forwarding enable/disable.
20	1	Non	non	Non-local Source Routing enable/disable.
21	8+	Policy Filter	policy-filter	Policy Filter.
22	2	Maximum Datagram Reassembly Size	maximum-datagram-reassembly-size	Maximum Datagram Reassembly Size.
23	1	Default IP Time	default-ip-time	Default IP Time-to-live.
24	4	Path MTU Aging Timeout	path-mtu-aging-timeout	Path MTU Aging Timeout.
25	2+	Path MTU Plateau Table	path-mtu-plateau-table	Path MTU Plateau Table.
26	2	Interface MTU	interface-mtu	Interface MTU.
27	1	All Subnets are Local	all-subnets-are-local	All Subnets are Local.
28	4	Broadcast Address	broadcast-address	Broadcast Address.
29	1	Perform Mask Discovery	perform-mask-discovery	Perform Mask Discovery.
30	1	Mask supplier	mask-supplier	Mask supplier.
31	1	Perform router discovery	perform-router-discovery	Perform router discovery.
32	4	Router solicitation address	router-solicitation-address	Router solicitation address.
33	8+	Static routing table	static-routing-table	Static routing table.
34	1	Trailer encapsulation	trailer-encapsulation	Trailer encapsulation.
35	4	ARP cache timeout	arp-cache-timeout	ARP cache timeout.
36	1	Ethernet encapsulation	ethernet-encapsulation	Ethernet encapsulation.
37	1	Default TCP TTL	default-tcp-ttl	Default TCP TTL
38	4	TCP keepalive interval	tcp-keepalive-interval	TCP keepalive interval.
39	1	TCP keepalive garbage	tcp-keepalive-garbage	TCP keepalive garbage.
40	1+	Network Information Service domain	network-information-service-domain	Network Information Service domain.
41	4+	Network Information Servers	network-information-servers	Network Information Servers.
42	4+	NTP servers	ntp-servers	NTP servers.
43	1+	Vendor specific information	vendor-specific-information	Vendor specific information.
48	4+ 	X Window System Font Server	x-window-system-font-server	X Window System Font Server. 
49	4+ 	X Window System Display Manager	x-window-system-display-manager	X Window System Display Manager. 
50	4 	Requested IP Address	requested-ip-address	Requested IP Address. 
51	4 	IP address lease time	ip-address-lease-time	IP address lease time.
52	1 	Option overload	option-overload	Option overload. 
53	1	DHCP message type	dhcp-message-type	DHCP message type.
54	4 	Server identifier	server-identifier	Server identifier. 
55	1+ 	Parameter request list	parameter-request-list	Parameter request list. 
56	1+ 	Message	message	Message. 
57	2 	Maximum DHCP message size	maximum-dhcp-message-size	Maximum DHCP message size. 
58	4 	Renew time value	renew-time-value	Renew time value. 
59	4 	Rebinding time value	rebinding-time-value	Rebinding time value. 
60	1+ 	Class	class	Class-identifier. 
66	1+ 	TFTP server name	tftp-server-name	TFTP server name. 
67	1+ 	Bootfile name	bootfile-name	Bootfile name. 
68	0+ 	Mobile IP Home Agent	mobile-ip-home-agent	Mobile IP Home Agent. 
69	4+ 	Simple Mail Transport Protocol Server	simple-mail-transport-protocol-server	Simple Mail Transport Protocol Server. 
70	4+ 	Post Office Protocol Server	post-office-protocol-server	Post Office Protocol Server. 
71	4+ 	Network News Transport Protocol Server	network-news-transport-protocol-server	Network News Transport Protocol Server. 
72	4+ 	Default World Wide Web Server	default-world-wide-web-server	Default World Wide Web Server. 
73	4+ 	Default Finger Server	default-finger-server	Default Finger Server. 
74	4+ 	Default Internet Relay Chat Server	default-internet-relay-chat-server	Default Internet Relay Chat Server. 
75	4+ 	StreetTalk Server	streettalk-server	StreetTalk Server. 
76	4+ 	StreetTalk Directory Assistance Server	streettalk-directory-assistance-server	StreetTalk Directory Assistance Server. 
77	Variable. 	User Class Information	user-class-information	User Class Information. 
78	Variable. 	SLP Directory Agent	slp-directory-agent	SLP Directory Agent. 
79	Variable. 	SLP Service Scope	slp-service-scope	SLP Service Scope. 
80	0	Rapid Commit	rapid-commit	Rapid Commit.
81	4+.	FQDN	fqdn	FQDN, Fully Qualified Domain Name.
82	Variable.	Relay Agent Information	relay-agent-information	Relay Agent Information.
83	14+	Internet Storage Name Service	internet-storage-name-service	Internet Storage Name Service.
85	Variable.	NDS servers	nds-servers	NDS servers.
86 	Variable. 	NDS tree name	nds-tree-name	NDS tree name. 
87 	Variable. 	NDS context	nds-context	NDS context. 
88	Variable.	BCMCS Controller Domain Name list	bcmcs-controller-domain-name-list	BCMCS Controller Domain Name list.
89	4+	BCMCS Controller IPv4 address list	bcmcs-controller-ipv4-address-list	BCMCS Controller IPv4 address list.
90 	Variable. 	Authentication	authentication	Authentication. 
92	4n	associated	associated	associated-ip.
93	Variable.	Client System Architecture Type	client-system-architecture-type	Client System Architecture Type.
94 	Variable.	Client Network Interface Identifier	client-network-interface-identifier	Client Network Interface Identifier.
95 	Variable. 	LDAP	ldap	LDAP, Lightweight Directory Access Protocol. 
97	Variable.	Client Machine Identifier	client-machine-identifier	Client Machine Identifier.
98 	 	Open Group	open-group	Open Group User Authentication. 
100	 	IEEE 1003	ieee-1003	IEEE 1003.1 TZ String.
101	 	Reference to the TZ Database	reference-to-the-tz-database	Reference to the TZ Database.
112 	Variable. 	NetInfo Parent Server Address	netinfo-parent-server-address	NetInfo Parent Server Address. 
113 	Variable. 	NetInfo Parent Server Tag	netinfo-parent-server-tag	NetInfo Parent Server Tag. 
114 	Variable. 	URL	url	URL. 
116 	1 	Auto	auto	Auto-Configure 
117 	2+ 	Name Service Search	name-service-search	Name Service Search. 
118	4	Subnet Selection	subnet-selection	Subnet Selection.
119	Variable.	DNS domain search list	dns-domain-search-list	DNS domain search list.
120	Variable.	SIP Servers DHCP Option	sip-servers-dhcp-option	SIP Servers DHCP Option.
121	5+	Classless Static Route Option	classless-static-route-option	Classless Static Route Option.
122	Variable.	CCC	ccc	CCC, CableLabs Client Configuration.
128	 	TFPT Server IP address	tfpt-server-ip-address	TFPT Server IP address.
129	 	Call Server IP address	call-server-ip-address	Call Server IP address.
130	 	Discrimination string	discrimination-string	Discrimination string.
131	 	Remote statistics server IP address	remote-statistics-server-ip-address	Remote statistics server IP address.
134	 	Diffserv Code Point	diffserv-code-point	Diffserv Code Point.
135	 	HTTP Proxy for phone	http-proxy-for-phone	HTTP Proxy for phone-specific applications.
136	 	OPTION	option	OPTION_PANA_AGENT.
150	 	TFTP server address	tftp-server-address	TFTP server address.
176	 	IP Telephone	ip-telephone	IP Telephone.
220	 	Subnet Allocation	subnet-allocation	Subnet Allocation.
221	 	Virtual Subnet Selection	virtual-subnet-selection	Virtual Subnet Selection.
254	 	Private use	private-use	Private use.
255	0	End	end	End.
\.

CREATE TABLE dhcp_options_to_dhcp_groups (
	id				SERIAL PRIMARY KEY,
	gid				integer REFERENCES dhcp_groups(id) ON DELETE CASCADE ON UPDATE CASCADE,
	oid				integer REFERENCES dhcp_options(id) ON DELETE RESTRICT, -- restrict or cascade for this?
	value			bytea,
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	unique( gid, oid, value )
);

CREATE INDEX dhcp_options_to_dhcp_groups_gid_oid_index ON dhcp_options_to_dhcp_groups(gid,oid);

CREATE TABLE hosts (
	mac				macaddr PRIMARY KEY,
	hostname		varchar UNIQUE NOT NULL,
	description		text,
	dhcp_group		integer REFERENCES dhcp_groups(id) ON DELETE RESTRICT ON UPDATE CASCADE,
	expires			timestamp NOT NULL,
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT
);

-- Should this be split into multiple indexes ... err... indices... whatever
CREATE INDEX hosts_mac_hostname_dhcp_group_index ON hosts(mac,hostname,description);

INSERT INTO hosts (mac, hostname, description, expires, changed_by) VALUES ( 'FFFFFFFFFFFF', 'ORPHANED', 'Records with unclear ownership', '1/1/1970', 1 );

CREATE TABLE hosts_to_groups (
	-- Associate hosts with groups
	id				SERIAL PRIMARY KEY,
	mac				macaddr NOT NULL REFERENCES hosts(mac) ON DELETE CASCADE ON UPDATE CASCADE,
	gid				integer NOT NULL REFERENCES groups(id) ON DELETE CASCADE ON UPDATE CASCADE,
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	UNIQUE (mac,gid)
);

CREATE INDEX hosts_to_groups_mac_gid_index ON hosts_to_groups(mac,gid);

CREATE TABLE pools (
	id			SERIAL PRIMARY KEY,
	name		varchar NOT NULL,
	description	text,
	-- FIXME: these would make for _really_ ugly queries...  need a better way to get this functionality
	-- Allow unknown MAC addresses?
	allow_unknown	BOOLEAN NOT NULL DEFAULT FALSE,
	lease_time		integer NOT NULL,
	-- Allow known MAC addresses (ie. listed in pool_access)?
	--allow_known	BOOLEAN NOT NULL DEFAULT TRUE
	dhcp_group		INTEGER REFERENCES dhcp_groups(id) ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE TABLE pools_to_groups (
	id			SERIAL PRIMARY KEY,
	pool		INTEGER NOT NULL REFERENCES pools(id) ON DELETE CASCADE ON UPDATE CASCADE,
	gid			INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE hosts_to_pools (
	id			SERIAL PRIMARY KEY,
	-- Allow this mac to get addresses from this pool.
	mac			MACADDR NOT NULL REFERENCES hosts(mac) ON DELETE CASCADE ON UPDATE CASCADE,
	pool_id		INTEGER NOT NULL REFERENCES pools(id) ON DELETE CASCADE ON UPDATE CASCADE,
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT
);

CREATE TABLE networks (
	network			cidr PRIMARY KEY,
	name			varchar(255),
	gateway			inet,
	description		text,
	dhcp_group		integer REFERENCES dhcp_groups(id) ON DELETE RESTRICT ON UPDATE CASCADE,
	shared_network	integer REFERENCES shared_networks(id) ON DELETE RESTRICT ON UPDATE CASCADE,
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT
);

CREATE TABLE addresses (
	address		inet PRIMARY KEY,
	mac			macaddr REFERENCES hosts(mac) ON DELETE SET NULL ON UPDATE CASCADE,
	pool		INTEGER DEFAULT NULL REFERENCES pools(id) ON DELETE SET DEFAULT ON UPDATE CASCADE,
	--CHECK ( mac IS NULL OR pool IS NULL )
	-- Specify that this address is specail: either a network address, a broadcast address, or maybe a gateway.
	reserved	boolean DEFAULT FALSE,
	network		cidr REFERENCES networks(network) NOT NULL,
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	CHECK (( mac IS NULL AND pool IS NULL ) OR (mac IS NULL AND reserved IS FALSE) OR (pool IS NULL AND reserved IS FALSE)),
	CHECK ( address <<= network )
);

CREATE TABLE leases (
	address		inet REFERENCES addresses(address) ON DELETE CASCADE PRIMARY KEY,
	mac			MACADDR UNIQUE, -- TODO: set ends to NULL also
	abandoned	boolean NOT NULL DEFAULT FALSE,
	-- Server that granted the lease, FIXME: make a new table?
	server		varchar,
	starts		timestamp DEFAULT NOW() NOT NULL,
	ends		timestamp NOT NULL,
	CHECK ( ( (mac IS NOT NULL AND abandoned = FALSE) OR (mac IS NULL AND abandoned = TRUE) ) AND starts <= NOW() AND ends > NOW() )
);

CREATE TABLE attributes (
	id				SERIAL PRIMARY KEY,
	name			varchar(255) UNIQUE NOT NULL,
	description		text,
	structured		boolean NOT NULL DEFAULT FALSE,
	required		boolean NOT NULL DEFAULT FALSE,
	validation		text DEFAULT NULL,
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT
);

CREATE TABLE structured_attribute_values (
	id				SERIAL PRIMARY KEY,
	aid				integer NOT NULL REFERENCES attributes(id) ON DELETE CASCADE ON UPDATE CASCADE,
	value			text NOT NULL,
	is_default			boolean NOT NULL DEFAULT FALSE,
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	UNIQUE (aid,value)
);

CREATE TABLE structured_attributes_to_hosts (
	id				SERIAL PRIMARY KEY,
	mac				MACADDR NOT NULL REFERENCES hosts(mac),
	avid				integer REFERENCES attribute_values(id) NOT NULL,
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	UNIQUE(mac,avid)
);

CREATE UNIQUE INDEX structured_attributes_to_hosts_unique_default_idx ON structured_attributes_to_hosts(avid) WHERE is_default = TRUE;

CREATE TABLE freeform_attributes_to_hosts (
	id				SERIAL PRIMARY KEY,
	mac				MACADDR NOT NULL REFERENCES hosts(mac),
	aid				integer NOT NULL REFERENCES attributes(id) ON DELETE RESTRICT,
	value			text NOT NULL,
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	UNIQUE(mac,aid,value)
);

CREATE VIEW attributes_to_hosts AS
(
        (SELECT a.id as aid, a.name as name, a.structured, a.required,
                        sa2h.mac, sa2h.avid, sav.value
                FROM attributes a
                JOIN structured_attribute_values sav
                        ON sav.aid = a.id
                JOIN structured_attributes_to_hosts sa2h
                        ON sav.id = sa2h.avid
        )
        UNION
        (SELECT a.id as aid, a.name as name, a.structured, a.required,
                        fa2h.mac, NULL as avid, fa2h.value
                FROM attributes a
                JOIN freeform_attributes_to_hosts fa2h
                        ON a.id = fa2h.aid
        )
);

-- Domains, records, and supermasters are more or less from the PowerDNS schema
CREATE TABLE domains (
	id				SERIAL PRIMARY KEY,
	name			VARCHAR(255) NOT NULL,
	master			VARCHAR(128) DEFAULT NULL,
	last_check		INT DEFAULT NULL,
	type			VARCHAR(6) NOT NULL,
	notified_serial	INT DEFAULT NULL, 
	account			VARCHAR(40) DEFAULT NULL,
	
	-- Non-PowerDNS schema items:
	description		text,
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX name_index ON domains(name);

CREATE TABLE domains_to_groups (
	id				SERIAL PRIMARY KEY,
	did				integer NOT NULL REFERENCES domains(id) ON DELETE CASCADE ON UPDATE CASCADE,
	gid				integer NOT NULL REFERENCES groups(id) ON DELETE CASCADE ON UPDATE CASCADE,
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	UNIQUE (did,gid)
);

CREATE TABLE dns_types (
	id				INTEGER PRIMARY KEY,
	name			varchar(16),
	description		text,
	min_permissions	BIT(8) NOT NULL DEFAULT B'00000000' REFERENCES permissions(id) ON DELETE RESTRICT
);

CREATE INDEX dns_types_id_index ON dns_types(id);

COPY dns_types ( id, name, description ) FROM stdin;
1	A	a host address [RFC 1035]
2	NS	an authoritative name server [RFC 1035]
3	MD	a mail destination (Obsolete - use MX) [RFC 1035]
4	MF	a mail forwarder (Obsolete - use MX) [RFC 1035]
5	CNAME	the canonical name for an alias [RFC 1035]
6	SOA	marks the start of a zone of authority [RFC 1035]
7	MB	a mailbox domain name (EXPERIMENTAL) [RFC 1035]
8	MG	a mail group member (EXPERIMENTAL) [RFC 1035]
9	MR	a mail rename domain name (EXPERIMENTAL)[RFC 1035]
10	NULL	a null RR (EXPERIMENTAL) [RFC 1035]
11	WKS	a well known service description [RFC 1035]
12	PTR	a domain name pointer [RFC 1035]
13	HINFO	host information [RFC 1035]
14	MINFO	mailbox or mail list information [RFC 1035]
15	MX	mail exchange [RFC 1035]
16	TXT	text strings [RFC 1035]
17	RP	for Responsible Person [RFC 1183]
18	AFSDB	for AFS Data Base location [RFC 1183]
19	X25	for X.25 PSDN address [RFC 1183]
20	ISDN	for ISDN address [RFC 1183]
21	RT	for Route Through [RFC 1183]
22	NSAP	for NSAP address, NSAP style A record [RFC 1706]
23	NSAP-PTR	
24	SIG	for security signature [RFC 2535][RFC 3755][RFC 4034]
25	KEY	for security key [RFC 2535][RFC 3755][RFC 4034]
26	PX	X.400 mail mapping information [RFC 2163]
27	GPOS	Geographical Position [RFC 1712]
28	AAAA	IP6 Address [RFC 3596]
29	LOC	Location Information [RFC 1876]
30	NXT	Next Domain - OBSOLETE [RFC 2535][RFC 3755]
31	EID	Endpoint Identifier [Patton]
32	NIMLOC	Nimrod Locator [Patton]
33	SRV	Server Selection [RFC 2782]
34	ATMA	ATM Address [af-dans-0152.000]
35	NAPTR	Naming Authority Pointer [RFC 2168][RFC 2915]
36	KX	Key Exchanger [RFC 2230]
37	CERT	CERT [RFC 2538]
38	A6	A6 [RFC 2874][RFC 3226]
39	DNAME	DNAME [RFC 2672]
40	SINK	SINK [Eastlake]
41	OPT	OPT [RFC 2671]
42	APL	APL [RFC 3123]
43	DS	Delegation Signer [RFC 3658]
44	SSHFP	SSH Key Fingerprint [RFC 4255]
45	IPSECKEY	IPSECKEY [RFC 4025]
46	RRSIG	RRSIG [RFC 3755]
47	NSEC	NSEC [RFC 3755]
48	DNSKEY	DNSKEY [RFC 3755]
49	DHCID	DHCID [RFC 4701]
50	NSEC3	NSEC3 [RFC-ietf-dnsext-nsec3-13.txt]
51	NSEC3PARAM	NSEC3PARAM [RFC-ietf-dnsext-nsec3-13.txt]
55	HIP	Host Identity Protocol [RFC-ietf-hip-dns-09.txt]
99	SPF	[RFC 4408]
100	UINFO	[IANA-Reserved]
101	UID	[IANA-Reserved]
102	GID	[IANA-Reserved]
103	UNSPEC	[IANA-Reserved]
249	TKEY	Transaction Key [RFC 2930]
250	TSIG	Transaction Signature [RFC 2845]
251	IXFR	incremental transfer [RFC 1995]
252	AXFR	transfer of an entire zone [RFC 1035]
253	MAILB	mailbox-related RRs (MB, MG or MR) [RFC 1035]
254	MAILA	mail agent RRs (Obsolete - see MX) [RFC 1035]
32768	TA	DNSSEC Trust Authorities [Weiler]  13 December 2005
32769	DLV	DNSSEC Lookaside Validation [RFC 4431]
\.

-- Give normal users access to A, CNAME, MX, TXT, and SRV records
UPDATE dns_types
SET min_permissions = '00000100'
WHERE id IN (1, 5, 12, 16, 33, 28);
-- Give DEITY users access to NS, PTR, and SOA records
UPDATE dns_types
SET min_permissions = '11111111'
WHERE id IN (2, 6, 15);

CREATE TABLE dns_views (
	id			SERIAL PRIMARY KEY,
	name		VARCHAR(128) UNIQUE NOT NULL,
	description	text
);

CREATE TABLE dns_records (
	id				SERIAL PRIMARY KEY,
	-- DNS domain ID
	did				INTEGER NOT NULL REFERENCES domains(id) ON DELETE RESTRICT ON UPDATE CASCADE,
	-- DNS record type
	tid				INTEGER NOT NULL REFERENCES dns_types(id) ON UPDATE CASCADE,
	-- DNS view ID, NULL == all views.
	vid				INTEGER REFERENCES dns_views(id) ON DELETE RESTRICT,
	name			VARCHAR(255) NOT NULL,
	-- Exactly one of the following two columns must be NULL
	text_content	VARCHAR(255),
	ip_content		inet REFERENCES addresses(address) ON DELETE RESTRICT,
	ttl				INTEGER DEFAULT -1,
	priority		INTEGER,
	-- mac				macaddr REFERENCES hosts(mac) ON DELETE RESTRICT ON UPDATE CASCADE,
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	CHECK (((tid = 1 AND family(ip_content) = 4 OR tid = 28 AND family(ip_content) = 6)
	       	AND ip_content IS NOT NULL AND text_content IS NULL) OR (tid <> 1 AND tid <> 28 AND ip_content IS NULL AND text_content IS NOT NULL)),
	UNIQUE (name, vid, tid, text_content, ip_content) -- We don't really need duplicate records...
);

CREATE INDEX rec_name_index ON dns_records(name);
CREATE INDEX rec_type_index ON dns_records(name,tid);
CREATE INDEX rec_did_index ON dns_records(did);

-- The table for all dynamic DNS records managed by the DHCP server
CREATE TABLE dhcp_dns_records (
	id				SERIAL PRIMARY KEY,
	did				INTEGER NOT NULL REFERENCES domains(id) ON DELETE RESTRICT ON UPDATE CASCADE,
	name			VARCHAR(255) NOT NULL,
	ip_content		inet REFERENCES addresses(address) ON DELETE RESTRICT,
	ttl				INTEGER DEFAULT -1,
	changed		timestamp DEFAULT NOW()
);

CREATE TABLE pdns_zone_xfer (
	id				SERIAL PRIMARY KEY,
	domain_id		INTEGER NOT NULL REFERENCES domains(id) ON UPDATE CASCADE,
	name			VARCHAR(255) NOT NULL,
	type			VARCHAR(10) NOT NULL,
	content			VARCHAR(255) NOT NULL,
	ttl				INTEGER DEFAULT -1,
	priority		INTEGER,
	change_date		INTEGER
);

CREATE INDEX pdns_zone_xfer_name_index      ON pdns_zone_xfer(name);
CREATE INDEX pdns_zone_xfer_name_type_index ON pdns_zone_xfer(name,type);
CREATE INDEX pdns_zone_xfer_domain_id_index ON pdns_zone_xfer(domain_id);

CREATE VIEW records AS
	SELECT dns_records.id AS id, did AS domain_id, dns_records.name AS name,
		dns_types.name AS "type",
		text_content AS content,
		ttl, priority AS prio,
		EXTRACT(EPOCH FROM dns_records.changed)::integer AS change_date,
		dns_records.vid as view_id
	FROM dns_records JOIN dns_types ON dns_records.tid = dns_types.id
	WHERE tid != 1 AND tid != 28
	UNION
	SELECT dns_records.id AS id, did AS domain_id, dns_records.name AS name,
		dns_types.name AS "type",
		host(ip_content)::VARCHAR AS content,
		ttl, priority AS prio,
		EXTRACT(EPOCH FROM dns_records.changed)::integer AS change_date,
		dns_records.vid as view_id
	FROM dns_records JOIN dns_types ON dns_records.tid = dns_types.id
	WHERE tid = 1 OR tid = 28
	UNION
	SELECT dhcp_dns_records.id AS id, did AS domain_id, dhcp_dns_records.name AS name,
		'A' AS "type",
		host(ip_content)::VARCHAR AS content,
		ttl, NULL AS prio,
		EXTRACT(EPOCH FROM dhcp_dns_records.changed)::integer AS change_date,
		1 AS view_id
	FROM dhcp_dns_records
	UNION
	SELECT id, domain_id, name, "type", content, ttl, priority, change_date, NULL AS view_id FROM pdns_zone_xfer;

CREATE TABLE supermasters (
	id				SERIAL PRIMARY KEY,
	ip				VARCHAR(25) NOT NULL, 
	nameserver		VARCHAR(255) NOT NULL, 
	account			VARCHAR(40) DEFAULT NULL,
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT
);

CREATE TABLE networks_to_groups (
	id				SERIAL PRIMARY KEY,
	nid				cidr NOT NULL REFERENCES networks(network) ON DELETE CASCADE ON UPDATE CASCADE,
	gid				integer NOT NULL REFERENCES groups(id) ON DELETE CASCADE ON UPDATE CASCADE,
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	UNIQUE (nid,gid)
);

CREATE TABLE guest_tickets (
	id				SERIAL PRIMARY KEY,
	uid				integer NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
	ticket			varchar(255) UNIQUE NOT NULL,
	starts			timestamp NOT NULL,
	ends			timestamp NOT NULL,
	description		text,
	CHECK ( starts < ends )
);

CREATE TABLE expiration_types (
	id				SERIAL PRIMARY KEY,
	expiration		interval,
	min_permissions	BIT(8) NOT NULL REFERENCES permissions(id) ON DELETE RESTRICT
);

INSERT INTO expiration_types (expiration, min_permissions) VALUES ( '1 millennium', B'11111111' );
INSERT INTO expiration_types (expiration, min_permissions) VALUES ( '1 day', B'00000000' );
INSERT INTO expiration_types (expiration, min_permissions) VALUES ( '1 week', B'00000000' );
INSERT INTO expiration_types (expiration, min_permissions) VALUES ( '1 month', B'00000000' );
INSERT INTO expiration_types (expiration, min_permissions) VALUES ( '6 months', B'00000000' );
INSERT INTO expiration_types (expiration, min_permissions) VALUES ( '1 year', B'00000000' );
INSERT INTO expiration_types (expiration, min_permissions) VALUES ( '2 years', B'11111111' );

CREATE TABLE notifications (
	id				SERIAL PRIMARY KEY,
	notification	interval,
	min_permissions	BIT(8) NOT NULL REFERENCES permissions(id) ON DELETE RESTRICT
);

-- No notification type for "don't notify" ... just don't insert the relation into notifications_to_hosts
INSERT INTO notifications (notification, min_permissions) VALUES ( '2 days', B'00000000' );
INSERT INTO notifications (notification, min_permissions) VALUES ( '14 days', B'00000000' );

CREATE TABLE notifications_to_hosts (
	id				SERIAL PRIMARY KEY,
	nid				integer NOT NULL REFERENCES notifications(id) ON DELETE CASCADE ON UPDATE CASCADE,
	mac				macaddr NOT NULL REFERENCES hosts(mac) ON DELETE CASCADE ON UPDATE CASCADE,
	UNIQUE (mac,nid)
);

CREATE TABLE disabled (
	mac     macaddr PRIMARY KEY,
	reason  text,
	disabled timestamp default NOW(),
	disabled_by integer REFERENCES users(id) NOT NULL
);

CREATE TABLE vlans (
	id smallint PRIMARY KEY,
	name varchar(12) NOT NULL, -- our HP switches
	description text,
	changed timestamp default NOW(),
	changed_by integer REFERENCES users(id) NOT NULL,
	CHECK (id > 0 AND id < 4096)
);

CREATE TABLE networks_to_vlans (
	network cidr references networks(network) PRIMARY KEY,
	vlan smallint REFERENCES vlans(id) NOT NULL,
	changed timestamp default NOW(),
	changed_by integer REFERENCES users(id) NOT NULL
);

CREATE TABLE kvp (
	id 	SERIAL NOT NULL,
	key	text NOT NULL,
	value	text NOT NULL
);

