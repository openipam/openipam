CREATE OR REPLACE FUNCTION update_from_ipam() RETURNS text AS $$
DECLARE
	need_vlan_data_update boolean;
	need_switch_data_update boolean;
BEGIN
	PERFORM dblink_connect('prod_openipam_db',
		'dbname=prod_openipam host=newdb1.ipam.usu.edu user=radius password=HcHe0o9MxXTDFxMXaUCs0bJ4QyoQqN84');
	
	CREATE TABLE temp_last_ipam_update AS (
		-- I'm not too worried about running this twice in a row after an update, so I'll be lazy
		SELECT * FROM dblink(
			'prod_openipam_db',
			'SELECT ''vlan_data'', max(hosts_log.trigger_changed) FROM addresses AS addr JOIN networks_to_vlans AS n2v ON addr.network = n2v.network JOIN hosts_log ON addr.mac = hosts_log.mac UNION SELECT ''switch_data'', max(hosts_to_groups_log.trigger_changed) FROM hosts_to_groups_log WHERE hosts_to_groups_log.gid = (SELECT id FROM groups WHERE name=''switches'')'
		)
		AS (table_name varchar, updated timestamptz)
	);

	SELECT COALESCE(temp_ipam.updated > last_ipam.updated OR last_update.updated < NOW() - interval '1 hour', TRUE)
	       	INTO need_vlan_data_update
       		FROM temp_last_ipam_update AS temp_ipam
	       	JOIN last_ipam_update AS last_ipam ON temp_ipam.table_name = last_ipam.table_name
	       	JOIN last_update ON last_update.table_name = temp_ipam.table_name
		WHERE temp_ipam.table_name = 'vlan_data';
	RAISE NOTICE 'need_vlan_data_update: %', need_vlan_data_update;

	SELECT COALESCE(temp_ipam.updated > last_ipam.updated OR last_update.updated < NOW() - interval '1 hour', TRUE)
	       	INTO need_switch_data_update
       		FROM temp_last_ipam_update AS temp_ipam
	       	JOIN last_ipam_update AS last_ipam ON temp_ipam.table_name = last_ipam.table_name
	       	JOIN last_update ON last_update.table_name = temp_ipam.table_name
		WHERE temp_ipam.table_name = 'switch_data';
	RAISE NOTICE 'need_switch_data_update: %', need_switch_data_update;

	ALTER TABLE last_ipam_update RENAME TO old_last_ipam_update;
	ALTER TABLE temp_last_ipam_update RENAME TO last_ipam_update;
	DROP TABLE old_last_ipam_update;


	IF need_vlan_data_update THEN
		CREATE TABLE temp_vlan_data AS (
			SELECT * FROM dblink(
				'prod_openipam_db',
				'SELECT addresses.mac, networks_to_vlans.vlan FROM addresses JOIN networks_to_vlans ON addresses.network = networks_to_vlans.network WHERE addresses.mac IS NOT NULL'
			)
			AS (mac macaddr, vlan smallint)
		);
		ALTER TABLE vlan_data RENAME TO old_vlan_data;
		ALTER TABLE temp_vlan_data RENAME TO vlan_data;
		DROP TABLE old_vlan_data;

		CREATE TABLE temp_radreply AS (
			SELECT 0 AS id, replace(mac::varchar,':','-') AS username,
					'Tunnel-Type' AS attribute,
					'=' AS op,
					'VLAN' AS value
				FROM vlan_data
			UNION SELECT 1 AS id, replace(mac::varchar,':','-') AS username,
					'Tunnel-Medium-Type' AS attribute,
					'=' AS op,
					'IEEE-802' AS value
				FROM vlan_data
			UNION SELECT 2 AS id, replace(mac::varchar,':','-') AS username,
					'Tunnel-Private-Group-ID' AS attribute,
					'=' AS op,
					vlan::varchar AS value
				FROM vlan_data
			UNION SELECT 3 AS id, replace(mac::varchar,':','-') AS username,
					'Fall-Through' AS attribute,
					'=' AS op,
					'Yes' AS value
				FROM vlan_data
		);
		ALTER TABLE radreply RENAME TO old_radreply;
		ALTER TABLE temp_radreply RENAME TO radreply;
		DROP TABLE old_radreply;

		CREATE TABLE temp_radcheck AS (
			SELECT 0 AS id, replace(mac::varchar,':','-') AS username,
					'Cleartext-Password'::varchar AS attribute,
					':='::varchar AS op,
					replace(mac::varchar,':','-') AS value
				FROM vlan_data
		);
		ALTER TABLE radcheck RENAME TO old_radcheck;
		ALTER TABLE temp_radcheck RENAME TO radcheck;
		DROP TABLE old_radcheck;
		
		UPDATE last_update SET updated=NOW() WHERE table_name = 'vlan_data';
	END IF;

	IF need_switch_data_update THEN
		CREATE TABLE temp_switch_data AS (
			SELECT * FROM dblink(
				'prod_openipam_db',
				'SELECT addresses.mac, addresses.address FROM addresses JOIN hosts_to_groups ON addresses.mac = hosts_to_groups.mac WHERE hosts_to_groups.gid = (SELECT id FROM groups WHERE groups.name = ''switches'')'
			)
			AS (mac macaddr, address inet)
		);

		ALTER TABLE switch_data RENAME TO old_switch_data;
		ALTER TABLE temp_switch_data RENAME TO switch_data;

		ALTER VIEW nas RENAME TO old_nas;
		CREATE VIEW nas AS (SELECT 0::integer AS id, switch_data.address::varchar as nasname,
		       ''::varchar AS shortname, 'other'::varchar AS type, NULL::int as ports,
		       'radius-mac-auth-sucks'::varchar(60) as secret,
		       ''::varchar AS community, ''::varchar AS description FROM switch_data);
		DROP VIEW old_nas;

		DROP TABLE old_switch_data;
		UPDATE last_update SET updated=NOW() WHERE table_name = 'switch_data';
		
	END IF;

	PERFORM dblink_disconnect('prod_openipam_db');

	RETURN 'OK';

END;
$$ LANGUAGE 'plpgsql';

UPDATE last_update SET updated='2000-01-01';

SELECT update_from_ipam();

