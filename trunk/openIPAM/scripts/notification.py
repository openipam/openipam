import sys
from openipam.backend.db import interface
from openipam.backend.auth.interfaces import LDAPInterface
from mail import *

db = interface.DBInterface(username='admin')
ldap_interface = LDAPInterface()

# Get list of people who need to be notified.
notification_list = db.find_expiring_hosts()

#print notification_list
#print notification_list[0].keys()

contactlist={}

dynamic_msg = """Subject: Your USU computer registration%(plural)s %(is_are)s about to expire

%(name)s,

The following computer%(plural)s %(is_are)s going to expire soon.
If you would like to continue using the USU network for another year:

1. Login to https://bluezone.usu.edu
2. Click "Renew" next to the following computer%(plural)s.

%(rows)s

If you have any questions, please contact the IT Service Desk.
Remember: never give your password to anyone, including USU employees.

IT Service Desk
Phone: 435.797.HELP (4357)
Toll Free: 1.877.878.8325
Email: servicedesk@usu.edu

"""

static_msg = """Subject: openIPAM Host Renewal Notice

%(name)s,

The following computer%(plural)s %(is_are)s going to expire soon.
To renew your servers and clients for another year:

1. Login to https://openipam.usu.edu
2. Click "Show my hosts expiring within 60 days"
3. Check the boxes next to those hosts you wish to renew
4. At the bottom, choose "Renew selected hosts" and click "Go"

Remember: help us keep up-to-date data. Don't renew hosts you don't need.

%(rows)s

If you have any questions, please contact the IT Service Desk.

IT Service Desk
Phone: 435.797.HELP (4357)
Toll Free: 1.877.878.8325
Email: servicedesk@usu.edu

"""

row_heading = "Hostname:                                MAC:                  Expiring in:   Description:"
row_fmt = "%(hostname)-40s %(mac)-22s %(days)3s days      %(description)s"



# Create a dictionary with keys of an A Number and values of the hosts about to expire.
for rowitem in notification_list:
	row_text = row_fmt % rowitem
	if contactlist.has_key('%(username)s' % rowitem):
		if not contactlist[rowitem['username']]['is_static'] and rowitem['is_static']:
			contactlist[rowitem['username']]['is_static'] = True
		contactlist['%(username)s' % rowitem]['rows'].append(row_text)
	else:
		contactlist['%(username)s' % rowitem] = {'rows':[row_heading,row_text,],'is_static':rowitem['is_static'],}
	# TODO: remove the items from the notification_to_hosts table.

for item in contactlist:
	try:
		ldapquery = ldap_interface._search_ldap(username=item)
	except Exception, e:
		print e
	#print item
	#print contactlist[item]
	contactlist[item]['name'] = ldapquery['name']
	contactlist[item]['email'] = ldapquery['email']
	contactlist[item]['email'] = ldapquery['email']
	num_rows = len(contactlist[item]['rows']) - 1
	contactlist[item]['rows'] = '\n'.join(contactlist[item]['rows'])
	contactlist[item]['plural'] = 's' if num_rows > 2 else ''
	contactlist[item]['is_are'] = 'are' if num_rows > 2 else 'is'
	if contactlist[item]['is_static']:
		emailtext = static_msg
	else:
		emailtext = dynamic_msg
	emailtext = emailtext % contactlist[item]
	print emailtext
	print '----------------------------------------------'

	# TODO: Fill in to field key value.
	#mail("mail.example.com", "noreply@example.com", "%()s" % ldapquery, "Your registered computer will expire soon", emailtext);

