BEGIN;

SELECT dblink_connect('gul_db','dbname=gulv3 user=openipam host=guldb.ipam.usu.edu');

DROP TABLE IF EXISTS gul_recent_arp_byaddress;
DROP TABLE IF EXISTS gul_recent_arp_bymac;

CREATE TABLE gul_recent_arp_byaddress
  AS SELECT * FROM dblink('gul_db',
    'SELECT arpentries.mac, arpentries.ip, coalesce(arpentries.stopstamp,now())::timestamptz FROM iplastarp JOIN arpentries ON iplastarp.arpid = arpentries.id;')
 AS (mac macaddr, address inet, stopstamp timestamptz);

CREATE INDEX gul_recent_arp_byaddress_address_idx ON gul_recent_arp_byaddress(address);

CREATE TABLE gul_recent_arp_bymac
  AS SELECT * FROM dblink('gul_db',
    'SELECT arpentries.mac, arpentries.ip, coalesce(arpentries.stopstamp,now())::timestamptz FROM maclastarp JOIN arpentries ON maclastarp.arpid = arpentries.id;')
 AS (mac macaddr, address inet, stopstamp timestamptz);

CREATE INDEX gul_recent_arp_bymac_mac_idx ON gul_recent_arp_bymac(mac);

GRANT SELECT ON gul_recent_arp_byaddress, gul_recent_arp_bymac TO openipam_readonly;

END;

