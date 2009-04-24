#!/bin/bash

SDIR=.
TABLE_LOG=1

DBNAME=$1

USER=openipam_user

[ -z $DBNAME ] && echo "usage: $0 db_name" && exit 1

echo "drop database $DBNAME; CREATE DATABASE $DBNAME; GRANT ALL ON DATABASE $DBNAME to $USER;" | sudo -u postgres psql

psql -U $USER -d $DBNAME -f $SDIR/dhcp_dns_schema.sql &> tmpoutput.create
psql -U $USER -d $DBNAME -f $SDIR/perms.sql 2>&1 >> tmpoutput.create
cat tmpoutput.create | grep -v "NOTICE\|CREATE\|INSERT"

if [ ! -z "$TABLE_LOG" ]; then
	sudo -u postgres psql -d $DBNAME -f $SDIR/table_log_setup.sql 2>&1 >> tmpoutput.create || ( echo "Failed to set up table_log, giving up" && exit 1 )
	cat $SDIR/dhcp_dns_schema.sql | grep -i "create table" | grep -v ^-- | sed "s/CREATE TABLE \([a-z_]\+\) \?(/SELECT public.table_log_init( 5, '\1');\nGRANT SELECT ON \1_log TO $USER;/" |	sudo -u postgres psql -d $DBNAME 2>&1 >> tmpoutput.create
fi


