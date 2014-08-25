GRANT SELECT ON records TO pdns;
GRANT INSERT,DELETE ON dns_records TO pdns;
GRANT SELECT,UPDATE ON domains TO pdns;
GRANT SELECT ON supermasters TO pdns;

GRANT SELECT ON permissions TO dhcp;
GRANT SELECT ON hosts TO dhcp;
GRANT SELECT ON hosts_to_pools TO dhcp;
GRANT SELECT ON addresses TO dhcp;
GRANT SELECT ON dhcp_groups TO dhcp;
GRANT SELECT ON dhcp_options TO dhcp;
GRANT SELECT ON dhcp_options_to_dhcp_groups TO dhcp;
GRANT SELECT ON shared_networks TO dhcp;
GRANT SELECT ON pools TO dhcp;
GRANT SELECT ON pools_to_groups TO dhcp;
GRANT SELECT ON networks TO dhcp;
GRANT SELECT ON domains TO dhcp;
GRANT ALL ON dhcp_dns_records_id_seq TO dhcp;
GRANT ALL ON leases TO dhcp;
GRANT ALL ON dhcp_dns_records TO dhcp;

