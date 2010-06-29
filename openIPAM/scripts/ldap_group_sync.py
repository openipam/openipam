#!/usr/bin/env python

import os

from openipam.config import auth_sources
from openipam.backend.db import interface

ipam_interface = interface.DBInterface(username='ldap_sync')
ipam_groups = ipam_interface.get_groups(name='ldap:%')

ldap_interface = auth_sources.interfaces[auth_sources.auth.sources.LDAP]

for group in ipam_groups:
	#print group
	ldap_users = []
	grouplist = [group['name'][len('ldap:'):]]
	for groupname in grouplist:
		ldap_filter = '(memberof=%s)' % groupname
		ldap_data = ldap_interface._query( basedn='ou=banner,dc=auth,dc=usu,dc=edu', filter=ldap_filter, attrs=['sAMAccountName','objectClass','dn'] )
		for user in ldap_data:
			#print user
			if 'group' in user[1]['objectClass']: # this is a sub-group, keep looking stuff up
				grouplist.append(user[0])
			if 'user' in user[1]['objectClass']:
				ldap_users.append(user)

	ldap_ids = set()
	for u in ldap_users:
		name = u[1]['sAMAccountName'][0]
		try:
			user = ipam_interface.get_users(username=name)
			ldap_ids.add(user[0]['id'])
		except:
			print "name=%s Failed to look up user %s for group %s" % (name,u,group)
	ipam_users = ipam_interface.get_users_to_groups( gid=group['id'] )
	ipam_ids = set()
	for u in ipam_users:
		ipam_ids.add(u['uid'])
	
	to_remove = ipam_ids.difference(ldap_ids)
	to_add = ldap_ids.difference(ipam_ids)

	for uid in to_remove:
		print "Removing %s from group %s" % (ipam_interface.get_users(uid=uid),group)
		try:
			ipam_interface.del_user_to_group(uid=uid, gid=group['id'])
		except:
			print "Failed"

	for uid in to_add:
		print "Adding %s to group %s" % (ipam_interface.get_users(uid=uid),group)
		try:
			ipam_interface.add_user_to_group(uid=uid, gid=group['id'], permissions=str(interface.perms.OWNER))
		except:
			print "Failed"

	if os.environ.has_key('DEBUG') and os.environ['DEBUG']:
		print "LDAP filter: %s" % ldap_filter
		print "LDAP users:"
		print ldap_users
		print "IPAM users:"
		print ipam_users
		print "To remove: %s, to add: %s" % (to_remove,to_add)


