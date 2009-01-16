import sys
sys.stdout = sys.stderr

import atexit
import threading
import cherrypy
from openipam.web.resource import webroot

cherrypy.config.update({'environment': 'embedded'})

# Yes, True. For some reason this fixes the Apache error
# [error] No handlers could be found for logger "cherrypy.access.148640524"
# This may only be necessary for 3.0 versions
cherrypy.config.update({'log.screen': True})

from openipam.config import frontend
cherrypy.config.update({
	'tools.sessions.on' : True,
	'tools.sessions.storage_type' : frontend.session_storage,
	'tools.sessions.storage_path' : frontend.session_dir,
	'tools.sessions.timeout' : frontend.session_timeout,
})

if cherrypy.engine.state == 0:
    cherrypy.engine.start(blocking=False)
    atexit.register(cherrypy.engine.stop)

application = cherrypy.Application(webroot.get_web_root(), None)

