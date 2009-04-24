"""

The beginnings of the openIPAM command line interface.

This module uses the python curses module for the CLI:
http://www.amk.ca/python/howto/curses/ 
http://docs.python.org/dev/howto/curses.html

"""

import curses
import string
import types

import sys
sys.path.insert(0, '/media/openipam/openIPAM/')

from openipam.utilities import validation

from openipam.backend.db import interface
db = interface.DBInterface(uid=1, username='admin', min_perms='11111111')

class CLIException(Exception):
	pass

def main(stdscr, *args, **kw):
	"""
	The main function hook passed to the curses wrapper
	"""
	
	global screen
	screen = stdscr
	
	main_menu()
	
	while True:
		try:
			screen.addstr(14, 0, "What would you like to do?\n")
			c = screen.getch()
			
			if c == ord('1'):
				cname_from = get_input("Adding CNAME: From where?")
				if not validation.is_fqdn(cname_from):
					raise CLIException("Invalid syntax: please use a fully-qualified domain name")
				
				cname_to = get_input("To where?")
				if not validation.is_fqdn(cname_to):
					raise CLIException("Invalid syntax: please use a fully-qualified domain name")
				
				record = db.get_dns_records(name=cname_from)
				if record:
					raise CLIException("Record already found: %s" % record)
				
				domain = db.get_domains(contains=cname_from)
				if not domain:
					raise CLIException("No domain found, couldn't add CNAME.")
				
				db.add_dns_record(name=cname_from, tid=5, text_content=cname_to, add_ptr=False)

				done_message("Done! Added CNAME: %s --> %s" % (cname_from, cname_to))
			elif c == ord('2'):
				domain = get_input("Adding domain:")
				if not validation.is_fqdn(domain):
					raise CLIException("Invalid syntax: please use a fully-qualified domain name")
				
				address = get_input("To where?")
				if not validation.is_ip(address):
					raise CLIException("Invalid syntax: please use an IP address")
				
				db._begin_transaction()
				try:
					db.add_domain( name=domain, type='MASTER', master=None )
					db.add_soa_record( name=domain, primary='root1.usu.edu', hostmaster='hostmaster@usu.edu' )
					db.add_dns_record( name=domain, tid=1, ip_content=address )
					
					db._commit()
				except:
					db._rollback()
					raise
					
				done_message("Done! Added domain %s --> %s" % (domain, address))
			elif c == ord('7'):
				sys.exit(0)
		except Exception, e:
			error_message(e)
	
def get_input(input):
	curses.echo()
	screen.addstr(20, 0, "%s\n" % input, curses.A_BOLD )
	s = screen.getstr()
	curses.noecho()
	clear_input()
	
	return s
	
def clear_input():
	screen.addstr(20, 0, " "*100)
	screen.addstr(21, 0, " "*100)
	screen.refresh()
	
def done_message(msg):
	screen.addstr(20, 0, msg, curses.A_BOLD )
	screen.refresh()
	
def error_message(msg):
	if type(msg) is not CLIException:
		raise msg
	screen.addstr(20, 0, str(msg), curses.A_BOLD | curses.A_REVERSE )
	screen.refresh()
	
	
def main_menu():	
	# Draw the onscreen field titles
	screen.addstr(1, 4, "1. Add a new CNAME", curses.A_BOLD )
	screen.addstr(2, 4, "2. Add a new delegated domain", curses.A_BOLD )
	screen.addstr(3, 4, "7. Exit", curses.A_BOLD )
	screen.refresh()

if __name__ == '__main__':
	curses.wrapper(main)

