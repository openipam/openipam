import email.Message
import smtplib
import time
import random
from socket import getfqdn
import math

random.seed()

hostname = getfqdn()

base64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890+/"


def base64enc(data):
    cur = data
    exponent = int(math.log(data, 64))
    vals = []
    while exponent >= 0:
        c = 64 ** exponent
        cm = cur / c
        cur = cur % c
        vals.append(base64map[cm])
        exponent -= 1
    return "".join(vals)


def generate_message_id(message):
    to = "NULL"
    if "To" in message:
        to = message["To"]
    t = int(time.time() * 1000000)
    t = base64enc(t)
    str = "<{}-{}-{}@{}>".format(
        t,
        base64enc(random.getrandbits(32)),
        to.replace("@", "_"),
        hostname,
    )
    return str


class Mailer:
    def __init__(self, server):
        self.server = server
        # can we increase efficiency somehow?
        # self.relay = smtplib.SMTP(server)

    def send_msg(
        self, to=None, bounce=None, sender=None, subject=None, body=None, headers=None
    ):
        if not headers:
            headers = {}
        if not bounce:
            bounce = sender
        message = email.Message.Message()
        message["To"] = to
        message["From"] = sender
        message["Subject"] = subject
        for k in headers:
            message[k] = headers[k]
        message.set_payload(body)

        self.single_msg(sender=bounce, to=to, message=message)

    def single_msg(self, sender, to, message):
        if "Date" not in message:
            message["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S %z")
        if "Message-ID" not in message:
            message["Message-ID"] = generate_message_id(message)
        relay = smtplib.SMTP(self.server)
        relay.sendmail(sender, to, message.as_string())
        relay.quit()

        # def __del__(self):
        # 	self.relay.quit()
