# Needs to be thread-safe, whatever we do...

import thread
import psycopg2
import types
from openipam.utilities import error

arp_lock = thread.allocate_lock()

min_permissions = '00000100'

from openipam.config.db import db_host, db_password, db_user

db_str = 'host=%s dbname=gulv3 username=%s db_password=%s' % (db_host, db_user, db_password)
#db_str = 'host=newdb1.ipam.usu.edu dbname=gulv3'

__conn = psycopg2.connect(db_str)

from openipam.utilities import validation

def execute(query):
	arp_lock.acquire()
	try:
		cursor = __conn.cursor()
		cursor.execute(query)
		result = cursor.fetchall()
		__conn.commit()
		arp_lock.release()
	except:
		__conn.rollback()
		arp_lock.release()
		raise
	return result

def interval_str(delta):
	days = delta.days
	hours = int( delta.seconds / 3600 )
	minutes = int( (delta.seconds % 3600) / 60 )
	parts = []
	if days:
		parts.append('%s day%s' % (days,'s' if days>1 else '') )
	if hours:
		parts.append('%s hour%s' % (hours, 's' if hours > 1 else '') )
	if minutes:
		parts.append('%s minute%s' % (minutes, 's' if minutes > 1 else '') )
	if not parts:
		return 'less than 1 minute ago'
	if len(parts) == 1:
		return '%s ago' % parts[0]
	return '%s and %s ago' % (', '.join(parts[:-1]), parts[-1])

def mk_dicts(data):
	newdata = []
	for r in data:
		newr = {'ip':r[0],'mac':r[1],}
		newr['ago'] = interval_str(r[2])
		newdata.append(newr)
	return newdata


def bymac(mac):
	print 'bymac(%s)' % mac
	if type(mac) == types.ListType:
		for i in mac:
			i = str(i)
			print i
			if not validation.is_mac(i):
				raise error.InvalidArgument('Not a valid mac address: %s' % i)
		cond = "mac IN ('%s')" % "','".join(mac)
	else:
		if not validation.is_mac(mac):
			raise error.InvalidArgument('Not a valid mac address: %s' % mac)
		cond = "mac = '%s'" % mac

	data = execute("SELECT ip, mac, COALESCE(NOW() - stopstamp, interval '0 minutes') AS last_seen FROM arpentries JOIN maclastarp ON arpentries.id = maclastarp.arpid WHERE %s;" % cond)
	return mk_dicts(data)

def byip(ip):
	print 'byip(%s)' % ip
	if type(ip) == types.ListType:
		for i in ip:
			i = str(i)
			print i
			if not validation.is_ip(i):
				raise error.InvalidArgument('Not a valid ip address: %s' % i)
		cond = "ip IN ('%s')" % "','".join(ip)
	else:
		if not validation.is_ip(ip):
			raise error.InvalidArgument('Not a valid ip address: %s' % ip)
		cond = "ip = '%s'" % ip

	data = execute("SELECT ip, mac, COALESCE(NOW() - stopstamp, interval '0 minutes') AS last_seen FROM arpentries JOIN iplastarp ON arpentries.id = iplastarp.arpid WHERE %s;" % cond)
	return mk_dicts(data)


