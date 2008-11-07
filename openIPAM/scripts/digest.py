import sys
from openipam.backend.db import interface
import time
import datetime
from mail import *

db = interface.DBBaseInterface(uid=1, username='admin', min_perms='11111111')

yt = time.localtime(time.time() - 86400) # Tuple holding values for yesterday, exactly 24 hours ago.
yesterday = datetime.date(yt[0],yt[1],yt[2])

changed_records = db.get_dns_records(None, None, None, None, yesterday)

list=[]
for record in changed_records:
	list.append( '%(name)s\t%(ip_content)s\t%(changed)s' % record)

emailtext = '\n'.join(list)

# FILL IN "TO" PARAMETER
mail('mail.example.com', sender='noreply@example.com', to='example@example.com', subject='Digest', text=emailtext)
