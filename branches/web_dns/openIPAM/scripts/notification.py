import sys
from openipam.backend.db import interface
from openipam.backend.auth.interfaces import LDAPInterface
from mail import *

db = interface.DBBaseInterface(uid=1, username='admin', min_perms='11111111')
ldap_interface = LDAPInterface()

# Get list of people who need to be notified.
notification_list = db.find_expiring_hosts()

#print notification_list
#print notification_list[0].keys()

contactlist={}

# Create a dictionary with keys of an A Number and values of the hosts about to expire.
for rowitem in notification_list:
	if contactlist.has_key('%(username)s' % rowitem):
		contactlist['%(username)s' % rowitem] += '%(mac)-22s%(hostname)-40s%(expires)-20s\n' % rowitem
	else:
		contactlist['%(username)s' % rowitem] = '%(mac)-22s%(hostname)-40s%(expires)-20s\n' % rowitem
	# TODO: remove the items from the notification_to_hosts table.

for item in contactlist:
	ldapquery = ldap_interface._search_ldap(username=item)
	#print item
	#print contactlist[item]
	emailtext = '''%(name)s,

The following computers registered to you are going to expire soon.
''' % ldapquery
	emailtext += '%-22s%-40s%-20s\n' % ("Mac Address:", "Hostname:", "Expiration Date")
	emailtext += contactlist[item]

	#print emailtext

	# TODO: Fill in to field key value.
	#mail("mail.example.com", "noreply@example.com", "%()s" % ldapquery, "Your registered computer will expire soon", emailtext);
