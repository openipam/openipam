ALTER TABLE groups_log ADD COLUMN changed timestamp;
ALTER TABLE groups_log ADD COLUMN changed_by integer;

ALTER TABLE internal_auth_log ADD COLUMN changed timestamp;
ALTER TABLE internal_auth_log ADD COLUMN changed_by integer;

ALTER TABLE shared_networks_log ADD COLUMN changed timestamp;
ALTER TABLE shared_networks_log ADD COLUMN changed_by integer;

ALTER TABLE dhcp_options_to_dhcp_groups_log ADD COLUMN changed timestamp;
ALTER TABLE dhcp_options_to_dhcp_groups_log ADD COLUMN changed_by integer;

ALTER TABLE hosts_to_pools_log ADD COLUMN changed timestamp;
ALTER TABLE hosts_to_pools_log ADD COLUMN changed_by integer;

ALTER TABLE addresses_log ADD COLUMN changed timestamp;
ALTER TABLE addresses_log ADD COLUMN changed_by integer;


DROP TABLE attributes_log;
DROP TABLE attribute_values_log;

