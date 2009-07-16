import sys
from openipam.backend.db import interface
from openipam.backend.auth.interfaces import LDAPInterface
#from mail import *
import scripts.mail

from openipam.config import auth_sources
from openipam.config import backend

db = interface.DBInterface(username='admin')
ldap_interface = LDAPInterface()

expiration_from = 'openipam@localhost'
expiration_reply_to = None


fromaddr = backend.expiration_from
replyaddr = backend.expiration_reply_to
bounceaddr = backend.bounce_addr

# Get list of people who need to be notified.
notification_list = db.find_expiring_hosts()

#print notification_list
#print notification_list[0].keys()

contactlist={}

dynamic_subject = '[USU:Important] Your USU computer registration%(plural)s %(is_are)s about to expire'
dynamic_msg = """%(name)s (%(username)s),

The following computer%(plural)s %(is_are)s going to expire soon.

If you would like to continue using the USU network for another year:

1. Log in to https://bluezone.usu.edu
2. Click "Renew" next to the following computer%(plural)s:

%(rows)s

If you have any questions, please contact the IT Service Desk.

Remember: never give your password to anyone, including USU employees.

-- 
IT Service Desk
Summer Hours:
Mon-Thu: 8:00am - 8:00pm
Friday: 8:00am - 6:00pm

Contact us at: 
Phone: 797-HELP (4357)
Toll Free: 877-878-8325
Email: servicedesk@usu.edu
http://footprints.usu.edu (Issue Tracking System)


"""

static_subject = '[USU:Important] openIPAM Host Renewal Notice'
static_msg = """%(name)s (%(username)s),

The following computer%(plural)s %(is_are)s going to expire soon.

To renew your servers and clients for another year:

1. Log in to https://openipam.usu.edu
2. Click "Show my hosts expiring within 60 days"
3. Check the boxes next to those hosts you wish to renew
4. At the bottom, choose "Renew selected hosts" and click "Go"

Remember: help us keep up-to-date data. Don't renew hosts you don't need.

%(rows)s

If you have any questions, please contact the IT Service Desk.

-- 
IT Service Desk
Summer Hours:
Mon-Thu: 8:00am - 8:00pm
Friday: 8:00am - 6:00pm

Contact us at: 
Phone: 797-HELP (4357)
Toll Free: 877-878-8325
Email: servicedesk@usu.edu
http://footprints.usu.edu (Issue Tracking System)


"""

row_heading = "Hostname:                                MAC:                  Expiring in:   Description:"
row_fmt = "%(hostname)-40s %(mac)-22s %(days)3s days      %(description)s"



# Create a dictionary with keys of an A Number and values of the hosts about to expire.
for rowitem in notification_list:
	row_text = row_fmt % rowitem
	if contactlist.has_key(rowitem['username']):
		if not contactlist[rowitem['username']]['is_static'] and rowitem['is_static']:
			contactlist[rowitem['username']]['is_static'] = True
		contactlist[rowitem['username']]['rows'].append(row_text)
		contactlist[rowitem['username']]['notifications'].append(rowitem['nid'])
	else:
		contactlist['%(username)s' % rowitem] = {'rows':[row_heading,row_text,],'is_static':rowitem['is_static'],'notifications':[rowitem['nid'],]}
	# TODO: remove the items from the notification_to_hosts table.


mailer = scripts.mail.Mailer(backend.smtp_host)

for item in contactlist:
	try:
		user = auth_sources.get_info(username=item)
		if not user:
			raise Exception('User %s not found' % item)
		if not user.email:
			raise Exception('User %s does not have preferred email set' % item)
	except Exception, e:
		sys.stderr.write( '%s: %s\n%s\n\n' % (e,item,'\n'.join(contactlist[item]['rows'])) )
		continue
	#print item
	#print contactlist[item]
	contactlist[item]['name'] = user.name #ldapquery['name']
	contactlist[item]['email'] = user.email #ldapquery['email']
	contactlist[item]['username'] = user.username #item
	num_rows = len(contactlist[item]['rows']) - 1
	contactlist[item]['rows'] = '\n'.join(contactlist[item]['rows'])
	contactlist[item]['plural'] = 's' if num_rows > 1 else ''
	contactlist[item]['is_are'] = 'are' if num_rows > 1 else 'is'
	if contactlist[item]['is_static']:
		emailtext = static_msg
		subject = static_subject % contactlist[item]
	else:
		emailtext = dynamic_msg
		subject = dynamic_subject % contactlist[item]
	emailtext = emailtext % contactlist[item]
	#print '----------------------------------------------'
	#print """To: %s\nFrom: %s\nReply-to: %s\nSubject: %s\n""" % (contactlist[item]['email'],fromaddr,replyaddr,subject)
	#print emailtext
	#print '----------------------------------------------'
	#print 'Delete: %s' % contactlist[item]['notifications']

	mailer.send_msg(to=contactlist[item]['email'], bounce=bounceaddr, sender=fromaddr, subject=subject, body=emailtext, headers={'Reply-to':replyaddr})
	db.del_notification_to_host(id=contactlist[item]['notifications'])

