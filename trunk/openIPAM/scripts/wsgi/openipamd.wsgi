import sys
sys.stdout = sys.stderr

import atexit
import threading
import cherrypy
from openipam.backend.webservices.xmlrpc import MainWebService
from openipam.config import backend


cherrypy.config.update({'environment': 'embedded'})

# Yes, True. For some reason this fixes the Apache error
# [error] No handlers could be found for logger "cherrypy.access.148640524"
# This may only be necessary for 3.0 versions
cherrypy.config.update({'log.screen': True})

cherrypy.config.update( {
		'tools.sessions.on' : True,
		'tools.sessions.locking' : 'explicit',
		'tools.sessions.storage_type' : backend.session_storage,
		'tools.sessions.storage_path' : backend.session_dir,
		'tools.sessions.timeout' : backend.session_timeout,
		'tools.gzip.on' : True,
		'tools.xmlrpc.allow_none' : True,
		'log.access_file' : backend.log_access, 
		'log.error_file' : backend.log_error,
		# XMLRPC stuff
		'tools.xmlrpc.on' : True,
		'request.dispatch' : cherrypy.dispatch.XMLRPCDispatcher(),
	} )

if cherrypy.engine.state == 0:
    cherrypy.engine.start(blocking=False)
    atexit.register(cherrypy.engine.stop)

application = cherrypy.Application(MainWebService(), None)

