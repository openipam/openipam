import sys
sys.stdout = sys.stderr

import atexit
import threading
import cherrypy
from openipam.web.resource import webroot

tb_fmt = """<html>
<head>
	<title>ERROR</title>

	<script type="text/javascript">
	<!--
	function toggleBox(szDivID, iState) // 1 visible, 0 hidden
	{
	   var obj = document.layers ? document.layers[szDivID] :
	   document.getElementById ?  document.getElementById(szDivID).style :
	   document.all[szDivID].style;
	   obj.display = document.layers ? (iState ? "block" : "none") :
	   (iState ? "block" : "none");
	}
	// -->
	</script>

	<style type="text/css">
	<!--
	.hidden  {display:none;}
	-->
	</style>

</head>
<body>
<div class="error">\n%s\n</div>
<input type="button" onClick="toggleBox('traceback',1);" value="Show traceback">
<div id='traceback' class="hidden">\n%s\n</div>
</body>
"""

def get_exc_str(exc):
	# FIXME: escape any characters special to html
	if hasattr(exc,'faultString'):
		return exc.faultString
	return str(exc).replace('<','&gt;').replace('>','&lt;')

def err():
	"""Replace the default error response with an HTML traceback from cgitb."""
	import cgitb, sys
	tb_str = cgitb.html(sys.exc_info())
	tb = tb_str[tb_str.find('\n')+1:]
	exc = sys.exc_info()[1]
	exc_str = get_exc_str(exc)
	def set_tb():
		cherrypy.response.body = tb_fmt % (exc_str, tb)
		#cherrypy.response.body = tb
		cherrypy.response.headers['Content-Length'] = None
	cherrypy.request.hooks.attach('after_error_response', set_tb)
cherrypy.tools.cgitb = cherrypy.Tool('before_error_response', err)

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

