ALTER TABLE groups ADD COLUMN changed timestamp;
ALTER TABLE groups ADD COLUMN changed_by integer;

UPDATE groups SET changed = '1970-01-01', changed_by=1;

ALTER TABLE groups ALTER COLUMN changed SET NOT NULL;
ALTER TABLE groups ALTER COLUMN changed SET DEFAULT NOW();
ALTER TABLE groups ALTER COLUMN changed_by SET NOT NULL;
ALTER TABLE groups ADD FOREIGN KEY (changed_by) REFERENCES users(id);




ALTER TABLE internal_auth ADD COLUMN changed timestamp;
ALTER TABLE internal_auth ADD COLUMN changed_by integer;

UPDATE internal_auth SET changed = '1970-01-01', changed_by=1;

ALTER TABLE internal_auth ALTER COLUMN changed SET NOT NULL;
ALTER TABLE internal_auth ALTER COLUMN changed SET DEFAULT NOW();
ALTER TABLE internal_auth ALTER COLUMN changed_by SET NOT NULL;
ALTER TABLE internal_auth ADD FOREIGN KEY (changed_by) REFERENCES users(id);





ALTER TABLE shared_networks ADD COLUMN changed timestamp;
ALTER TABLE shared_networks ADD COLUMN changed_by integer;

UPDATE shared_networks SET changed = '1970-01-01', changed_by=1;

ALTER TABLE shared_networks ALTER COLUMN changed SET NOT NULL;
ALTER TABLE shared_networks ALTER COLUMN changed SET DEFAULT NOW();
ALTER TABLE shared_networks ALTER COLUMN changed_by SET NOT NULL;
ALTER TABLE shared_networks ADD FOREIGN KEY (changed_by) REFERENCES users(id);




ALTER TABLE dhcp_options_to_dhcp_groups ADD COLUMN changed timestamp;
ALTER TABLE dhcp_options_to_dhcp_groups ADD COLUMN changed_by integer;

UPDATE dhcp_options_to_dhcp_groups SET changed = '1970-01-01', changed_by=1;

ALTER TABLE dhcp_options_to_dhcp_groups ALTER COLUMN changed SET NOT NULL;
ALTER TABLE dhcp_options_to_dhcp_groups ALTER COLUMN changed SET DEFAULT NOW();
ALTER TABLE dhcp_options_to_dhcp_groups ALTER COLUMN changed_by SET NOT NULL;
ALTER TABLE dhcp_options_to_dhcp_groups ADD FOREIGN KEY (changed_by) REFERENCES users(id);








ALTER TABLE hosts_to_pools ADD COLUMN changed timestamp;
ALTER TABLE hosts_to_pools ADD COLUMN changed_by integer;

UPDATE hosts_to_pools SET changed = '1970-01-01', changed_by=1;

ALTER TABLE hosts_to_pools ALTER COLUMN changed SET NOT NULL;
ALTER TABLE hosts_to_pools ALTER COLUMN changed SET DEFAULT NOW();
ALTER TABLE hosts_to_pools ALTER COLUMN changed_by SET NOT NULL;
ALTER TABLE hosts_to_pools ADD FOREIGN KEY (changed_by) REFERENCES users(id);










ALTER TABLE addresses ADD COLUMN changed timestamp;
ALTER TABLE addresses ADD COLUMN changed_by integer;

UPDATE addresses SET changed = '1970-01-01', changed_by=1;

ALTER TABLE addresses ALTER COLUMN changed SET NOT NULL;
ALTER TABLE addresses ALTER COLUMN changed SET DEFAULT NOW();
ALTER TABLE addresses ALTER COLUMN changed_by SET NOT NULL;
ALTER TABLE addresses ADD FOREIGN KEY (changed_by) REFERENCES users(id);





DROP TABLE attribute_values;
DROP TABLE attributes_to_hosts;
DROP TABLE attributes;

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
	value				text NOT NULL,
	is_default			boolean NOT NULL DEFAULT FALSE,
	changed				timestamp DEFAULT NOW(),
	changed_by			integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
	UNIQUE (aid,value)
);

CREATE TABLE structured_attributes_to_hosts (
	id				SERIAL PRIMARY KEY,
	mac				MACADDR NOT NULL REFERENCES hosts(mac),
	avid				integer REFERENCES structured_attribute_values(id) NOT NULL,
	changed				timestamp DEFAULT NOW(),
	changed_by			integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX structured_attributes_to_hosts_unique_default_idx ON structured_attributes_to_hosts(avid) WHERE is_default = TRUE;

CREATE TABLE freeform_attributes_to_hosts (
	id				SERIAL PRIMARY KEY,
	mac				MACADDR NOT NULL REFERENCES hosts(mac),
	aid				integer NOT NULL REFERENCES attributes(id) ON DELETE RESTRICT,
	value			text NOT NULL,
	changed			timestamp DEFAULT NOW(),
	changed_by		integer NOT NULL REFERENCES users(id) ON DELETE RESTRICT
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

CREATE TABLE kvp (
	id 	SERIAL NOT NULL,
	key	text NOT NULL,
	value	text NOT NULL
);

INSERT INTO kvp(key,value) VALUES ('schemaver','1.0');

