"""

Some miscellaneous resources for the front-end openIPAM interface

"""

import cherrypy


def redirect_to_referer():
	"""
	Raises a cherrypy.HTTPRedirect the referrering page
	
	And, yes, it's spelled 'referer' ...
	"""
	
	if cherrypy.request.headers.has_key('Referer'):
		raise cherrypy.HTTPRedirect(cherrypy.request.headers['Referer'])
	else:
		raise cherrypy.HTTPRedirect('/default')