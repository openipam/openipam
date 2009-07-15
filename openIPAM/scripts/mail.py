import email.Message
import smtplib
import time
import random
from socket import getfqdn
import math

random.seed()

hostname = getfqdn()

def mail(serverURL=None, sender='', to='', subject='', text=''):
	message = email.Message.Message()
	message["To"]      = to
	message["From"]    = sender
	message["Subject"] = subject
	message.set_payload(text)
	mailServer = smtplib.SMTP(serverURL)
	mailServer.sendmail(sender, to, message.as_string())
	mailServer.quit()

base64map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890+/'
def base64enc( data ):
	cur = data
	exponent = int(math.log(data,64))
	vals = []
	while exponent >= 0:
		c = 64**exponent
		cm = cur/c
		cur = cur%c
		vals.append(base64map[cm])
		exponent-=1
	return ''.join(vals)

def generate_message_id(message):
	parts = []
	to = 'NULL'
	if message.has_key('To'):
		to = message['To']
	t = int(time.time()*1000000)
	t = base64enc(t)
	str = '<%s-%s-%s@%s>' % (t,base64enc(random.getrandbits(32)),to.replace('@','_'),hostname)
	return str

class Mailer(object):
	def __init__(self, server):
		self.server = server
		# can we increase efficiency somehow?
		#self.relay = smtplib.SMTP(server)

	def send_msg( self, to=None, sender=None, subject=None, body=None, headers=None):
		if not headers:
			headers={}
		message = email.Message.Message()
		message["To"]      = to
		message["From"]    = sender
		message["Subject"] = subject
		for k in headers:
			message[k] = headers[k]
		message.set_payload(body)

		self.single_msg(sender=sender, to=to, message=message)

	def single_msg( self, sender, to, message):
		if not message.has_key('Date'):
			message['Date'] = time.strftime('%a, %d %b %H:%M:%S %z')
		if not message.has_key('Message-ID'):
			message['Message-ID'] = generate_message_id(message)
		relay = smtplib.SMTP(self.server)
		relay.sendmail(sender, to, message.as_string())
		relay.quit()

	#def __del__(self):
	#	self.relay.quit()


