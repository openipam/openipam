import email.Message
import smtplib

def mail(serverURL=None, sender='', to='', subject='', text=''):
	message = email.Message.Message()
	message["To"]      = to
	message["From"]    = sender
	message["Subject"] = subject
	message.set_payload(text)
	mailServer = smtplib.SMTP(serverURL)
	mailServer.sendmail(sender, to, message.as_string())
	mailServer.quit()
