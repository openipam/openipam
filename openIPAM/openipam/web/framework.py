import cherrypy
import types

from Cheetah.Template import Template
from openipam.utilities.perms import Perms
from openipam.config import frontend

perms = frontend.perms

class Basics(object):
	'''This class contains all of the common HTML that will wrap each individual pages content'''

	__topnavpos = None

	def __init__(self, section, javascript=""):
		self.__current_section = section
		self.__javascript = javascript
		
		self.__sections = { 'hosts' : '<a href="/hosts/">Manage Hosts</a>',
						'networks' : '<a href="/networks">Networks</a>',
						'domains' : '<a href="/domains">Domains</a>',
						'dns' : '<a href="/dns">Manage DNS</a>',
						'admin' : '<a href="/admin">Administration</a>',
						'access' : '<a href="/access">My Access</a>',
						'' : '' 
					}
		
		
		
	def begin(self, extra_headers=None):
		'''Combines the header, topbar, and topnav
		@param current_section: an integer denoting the index of which top nav link we're on'''
		html = self.header(extra_headers=extra_headers)
		html += self.topbar()
		html += self.topnav()
		return html

	def end(self):
		html = self.footer()
		return html

	#-----------------------------------------------------------------
	
	def wrap(self, maincontent=None, leftcontent=None, extra_headers='', filename=None, values=None):
		'''Wraps content with the headers, top navigation, and footer
		@param maincontent: a string of HTML for the inner page
		@param leftcontent: a strong of HTML for the leftnav
		'''
		
		# FIXME: once everything is transitioned over to Cheetah templates, (think about) 
		# remove maincontent, leftcontent, and extra_headers arguments
		if filename and values:

			# Make a template_keys variable that will always exist for every Cheetah template
			# so that templates can do things like #if 'hosts' in $template_keys:
			# and makes it so that all variables in a template are NOT required to pass in every time
			cherrypy.session.acquire_lock()
			try:
				values['template_keys'] = list(values.keys())
				values['has_admin_perms'] = ((Perms(cherrypy.session['min_permissions']) & perms.ADMIN) == perms.ADMIN)
				values['has_owner_perms'] = ((Perms(cherrypy.session['min_permissions']) & perms.OWNER) == perms.OWNER)
				values['has_deity_perms'] = ((Perms(cherrypy.session['min_permissions']) & perms.DEITY) == perms.DEITY)
				values['username'] = cherrypy.session['username']
			finally:
				cherrypy.session.release_lock()
			
			maincontent = Template(file=filename, searchList=values)
		
		text = []
		
		text.append('''
			%s
			<div id="main">''' % self.begin(extra_headers=extra_headers))
		
		if leftcontent is not None:
			text.append('''
				<div id="col1">
					<div id="col1_content" class="clearfix">
					%s
					</div>
				</div>
				<div id="col3">''' % leftcontent)
		else:
			text.append('''
				<div id="col3" style="margin:0pt;">''')
		
		text.append('''
					<div id="col3_content" class="clearfix">
					''')
		if values and "global_success" in values:
			text.append('''
							<div class="successMessage">'''+values['global_success']+'''</div>
						''')
		text.append('''
					<noscript>
						<div class="message"><div>JavaScript is required for openIPAM to function properly. Please enable JavaScript.</div></div>
					</noscript>
					<div id="globalMessage" class="hidden message"><!-- --></div>
					%s
					<div id="ie_clearing">&nbsp;</div>
				</div>
			</div><!-- end main --->
			%s ''' % (maincontent, self.end()))
		
		return ''.join(text)

	#-----------------------------------------------------------------
	
	def header(self, extra_headers=''):
		'''HTML beginning through page_margins div'''
		
		return '''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"><html>
<head>
	<title>openIPAM</title>
	<meta http-equiv="content-type" content="text/html; charset=utf-8" />
	<meta http-equiv="content-language" content="en" />
	<meta name="robots" content="noindex,nofollow" />
	%s
	<link href="/styles/css/main.css" rel="stylesheet" type="text/css" />
	<!--[if lte IE 7]>
	<link href="/styles/css/patch_layout.css" rel="stylesheet" type="text/css" />
	<![endif]-->
</head>
<body>
	<div id="page_margins">
''' % extra_headers
	
	#-----------------------------------------------------------------

	def topbar(self):
		'''The very top bar of page -- with Logout, About, etc.'''
		cherrypy.session.acquire_lock()
		try:
			return '''
			<div id="topnav">
				<a class="skip" title="skip link" href="#navigation">Skip to the navigation</a>
				<span class="hideme">.</span>
				<a class="skip" title="skip link" href="#main">Skip to the content</a>
				<span class="hideme">.</span>
				<a href="/logout">Logout %s</a> | 
			</div>''' % cherrypy.session['username']
		finally:
			cherrypy.session.release_lock()

	#-----------------------------------------------------------------
	
	def topnav(self):
		'''Everything from logo down to the navigation buttons
		@param selected: an integer denoting the index of which top nav link we're on'''
		
		cherrypy.session.acquire_lock()
		try:
			if 'min_permissions' not in cherrypy.session:
				raise error.SessionExpired("Permissions not in session, can't continue")
			
			if cherrypy.session['min_permissions'] == perms.DEITY:
				# The user has DEITY permissions
				__topnav_left_links = (self.__sections['hosts'],
								self.__sections['networks'],
								self.__sections['domains'],
								self.__sections['dns'])
		
				__topnav_right_links = (self.__sections['admin'],)
			else:
				# The user doesn't have DEITY permissions
				__topnav_left_links = (self.__sections['hosts'],
								self.__sections['dns'],
								self.__sections['access'])
		
				__topnav_right_links = ()
		finally:
			cherrypy.session.release_lock()
		
		text = []
		
		text.append('''
		<div id="page">
			<div id="header">
				<a href="/" onfocus="this.blur()"><img src="/images/logo/logo.png" /></a>
			</div>
			<div id="nav">
				<a id="navigation" name="navigation"></a>
				<div id="nav_main">
					<ul>
						''')
		for link in __topnav_left_links:
			if self.__sections[self.__current_section] == link:
				text.append('<li id="current">%s</li>' % link)
			else:
				text.append('<li>%s</li>' % link)
		
		text.append('''
					</ul>
					<ul class="rightbar">
						''')
		for link in __topnav_right_links:
			if self.__sections[self.__current_section] == link:
				text.append('<li id="current">%s</li>' % link)
			else:
				text.append('<li>%s</li>' % link)
		
		text.append('''
					</ul>
				</div>
			</div>''')
		
		return ''.join(text)
	
	#-----------------------------------------------------------------
	
	# footer - bottom bar and end HTML
	def footer(self):
		includes = []
		
		if type(self.__javascript) is tuple:
			for inc in self.__javascript:
				includes.append('<script type="text/javascript" src="%s"></script>' % inc)
		else:
			includes.append('<script type="text/javascript" src="%s"></script>' % self.__javascript)

		text = '''
			<div id="footer">
				Powered by <a href="http://www.openipam.org">openIPAM</a> - Produced by <a href="http://www.usu.edu">Utah State University</a> - <a href="http://it.usu.edu/">Information Technology</a>
			</div>
		</div><!-- end page -->
	</div><!-- end page margins -->
	<script type="text/javascript" src="/scripts/jquery/jquery.min.js"></script>
	<script type="text/javascript" src="/scripts/jquery.openipam.js"></script>
	<script type="text/javascript">
		$.openipam.init();
	</script>
	%s
</body>
</html>''' % ''.join(includes)
		
		return text

#-----------------------------------------------------------------

class Splash:
	def wrap(self, content):
		'''Wraps content of the login screen
		@param content: a string of HTML to wrap'''
		
		html = '''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
   "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
	<title>openIPAM</title>
	<meta http-equiv="Content-type" content="text/html; charset=utf-8" />
	<meta name="robots" content="noindex,nofollow" />
	<meta http-equiv="content-language" content="en" />
	
	<link href="/styles/css/main.css" rel="stylesheet" type="text/css" />
	<!--[if lte IE 7]>
	<link href="/styles/css/patch_layout.css" rel="stylesheet" type="text/css" />
	<![endif]-->

	<script type="text/javascript">
		function focusit() {
			document.getElementById('username').focus();
		}
		window.onload = focusit;
	</script>
</head>
<body class="login">
''' + content + '''
</body>
</html>
'''
		return html

	#-----------------------------------------------------------------
