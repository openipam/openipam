CREATE OR REPLACE FUNCTION update_gul_cache( connstr varchar ) RETURNS VOID AS $$
DECLARE
	lastupdate	varchar;
	updateinterval	varchar;

BEGIN

SELECT value FROM kvp WHERE key='last_gul_cache_update' FOR UPDATE INTO lastupdate;
IF NOT FOUND THEN
	INSERT INTO kvp(key,value) VALUES ('last_gul_cache_update','1970-01-01');
	SELECT value FROM kvp WHERE key='last_gul_cache_update' FOR UPDATE INTO lastupdate;
END IF;

SELECT value FROM kvp WHERE key='gul_cache_update_interval' INTO updateinterval;
IF NOT FOUND THEN
	INSERT INTO kvp(key,value) VALUES ('gul_cache_update_interval','5 minutes');
	SELECT value FROM kvp WHERE key='gul_cache_update_interval' INTO updateinterval;
END IF;


IF lastupdate::timestamptz > ( NOW() - updateinterval::interval ) THEN
	-- don't update at this time
	RAISE NOTICE 'Not updating due to gul_cache_update_interval';
	RETURN;
END IF;

RAISE NOTICE 'Beginning update';

PERFORM dblink_connect('gul_db',connstr);

CREATE TABLE new_gul_recent_arp_byaddress
  AS SELECT * FROM dblink('gul_db',
    'SELECT arpentries.mac, arpentries.ip, coalesce(arpentries.stopstamp,now())::timestamptz FROM iplastarp JOIN arpentries ON iplastarp.arpid = arpentries.id;')
 AS (mac macaddr, address inet, stopstamp timestamptz);

CREATE INDEX new_gul_recent_arp_byaddress_address_idx ON new_gul_recent_arp_byaddress(address);

CREATE TABLE new_gul_recent_arp_bymac
  AS SELECT * FROM dblink('gul_db',
    'SELECT arpentries.mac, arpentries.ip, coalesce(arpentries.stopstamp,now())::timestamptz FROM maclastarp JOIN arpentries ON maclastarp.arpid = arpentries.id;')
 AS (mac macaddr, address inet, stopstamp timestamptz);

CREATE INDEX new_gul_recent_arp_bymac_mac_idx ON new_gul_recent_arp_bymac(mac);

GRANT SELECT ON new_gul_recent_arp_byaddress, new_gul_recent_arp_bymac TO openipam_readonly;

UPDATE kvp SET value=NOW()::varchar WHERE key='last_gul_cache_update';

DROP TABLE IF EXISTS gul_recent_arp_byaddress;
DROP TABLE IF EXISTS gul_recent_arp_bymac;

ALTER TABLE new_gul_recent_arp_byaddress RENAME TO gul_recent_arp_byaddress;
ALTER INDEX new_gul_recent_arp_byaddress_address_idx RENAME TO gul_recent_arp_byaddress_address_idx;

ALTER TABLE new_gul_recent_arp_bymac RENAME TO gul_recent_arp_bymac;
ALTER INDEX new_gul_recent_arp_bymac_mac_idx RENAME TO gul_recent_arp_bymac_mac_idx;

PERFORM dblink_disconnect('gul_db');

RAISE NOTICE 'Update successful.';

END;

$$ LANGUAGE plpgsql;

