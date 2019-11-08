from openipam.backend.db import interface
import time
import datetime
from openipam.config import backend
import scripts.mail

senderaddr = backend.digest_from
toaddr = backend.digest_dest
smtpserver = backend.smtp_host
bounce = backend.bounce_addr

db = interface.DBInterface(username="admin")

yt = time.localtime(
    time.time() - 86400
)  # Tuple holding values for yesterday, exactly 24 hours ago.
yesterday = datetime.date(yt[0], yt[1], yt[2])

changed_records = db.get_dns_records(changed=yesterday)

list = []
PTR = 12
for record in changed_records:
    if record.tid != PTR:
        list.append("%(name)s\t%(ip_content)s\t%(changed)s" % record)

emailtext = "\n".join(list)

mailer = scripts.mail.Mailer(smtpserver)

mailer.send_msg(
    sender=senderaddr, to=toaddr, subject="openIPAM daily digest", body=emailtext
)
