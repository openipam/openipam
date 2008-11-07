from basepage import BasePage
from openipam.web.resource.submenu import submenu, OptionsSubmenu
from openipam.utilities import misc, error, validation
from openipam.utilities.perms import Perms
from openipam.web.resource.utils import redirect_to_referer
from openipam.config import frontend

import cherrypy
import framework

class DNS(BasePage):
	'''
	The DNS class. This includes all pages that are /dns/*
	'''

	def __init__(self):
		BasePage.__init__(self)
		
		# Object for wrapping HTML into the template
		self.__template = framework.Basics("dns", javascript=("/scripts/jquery/ui/jquery-ui-personalized.min.js", "/scripts/dns.js"))
	
	#------------------------  Private Functions  ------------------------
	
	def leftnav_options(self):
		'''
		Returns the html for the leftnav options on the Manage DNS tab
		'''
		
		options = ('Show only A records', 'Show only CNAMEs', 'Show only NS records')
		options_links = ('/dns/?show_a_records', '/dns/?show_cnames', '/dns/?show_ns')
		selected = (cherrypy.session['show_a_records'], cherrypy.session['show_cnames'], cherrypy.session['show_ns'])
		
		return OptionsSubmenu(values=options, links=options_links, title="Options", selected=selected)
	
	def get_leftnav(self, action="", show_options=True):
		return '%s' % (self.leftnav_options() if show_options else '')
	
	def get_dns(self, name = None, address = None, content = None, mac = None ):
		'''
		
		'''
		
		# Replace any wildcard stars with DB capable wildcards
		if name:
			name = name.replace("*", "%")
		if content:
			content = content.replace("*", "%")

		# Initialization
		values = {
			'name' : name,
			'address' : address,
			'content' : content,
			'order_by' : 'tid, name',
			'mac' : mac
			}

		# Set the limit if wildcard is in the search
		if name and ('%' in name):
			values['limit'] = cherrypy.session['dns_records_limit']
		
		#call webservice to get values
		dns_records = self.webservice.get_dns_records( values )
		
		# get permissions
		permissions = self.webservice.find_permissions_for_dns_records( { 'records' : dns_records } )
		
		# Translates type id into name
		dns_types = self.webservice.get_dns_types( {'make_dictionary' : True} )
		
		for record in dns_records:
			# dns_types = { '2' : { name : 'NS' },  }
			record['type'] = dns_types[str(record['tid'])]['name']
			record['has_modify_perm'] = ((Perms(permissions[0][str(record['id'])]) & frontend.perms.MODIFY) == frontend.perms.MODIFY)
			record['has_delete_perm'] = ((Perms(permissions[0][str(record['id'])]) & frontend.perms.DELETE) == frontend.perms.DELETE)
		
		# filtering based on selected options
		count = 0
		dns_results = []
		for record in dns_records:
			if ( (cherrypy.session['show_a_records'] and record['tid'] == 1)
			   and (cherrypy.session['show_ns'] and record['tid'] == 2)
			   and (cherrypy.session['show_cnames'] and record['tid'] == 5) ):
				dns_results.append(i)
			if (not cherrypy.session['show_a_records'] and not cherrypy.session['show_ns'] and not cherrypy.session['show_cnames']):
				return dns_records
			count += 1
		
		return dns_results
	
	#------------------------  Public Functions  ------------------------
	
	@cherrypy.expose
	def index(self, **kw):
		"""
		The DNS management page
		"""
		
		# Confirm user authentication
		self.check_session()
		
		# Toggle 'Show only A-records' and 'Show only CNAMES' and 'Show only NS records'
		if kw.has_key('show_a_records'):
			cherrypy.session['show_a_records'] = not cherrypy.session['show_a_records']
			redirect_to_referer()
		if kw.has_key('show_cnames'):
			cherrypy.session['show_cnames'] = not cherrypy.session['show_cnames']
			redirect_to_referer()
		if kw.has_key('show_ns'):
			cherrypy.session['show_ns'] = not cherrypy.session['show_ns']
			redirect_to_referer()
											    
		values = {}
		values['show_search_here'] = True
		values['title'] = 'DNS Search Results'
		values['dns_types'] = self.webservice.get_dns_types({ 'min_perms' : str(frontend.perms.READ), 'order_by' : 'name'  })
		
		return self.__template.wrap(leftcontent=self.get_leftnav(), filename='%s/templates/dns.tmpl'%frontend.static_dir, values=values)

	@cherrypy.expose
	def search(self, q=None, **kw):
		'''
		The search page where the search form POSTs
		'''
		
		# Confirm user authentication
		self.check_session()
		
		# Initialization
		values = {}
		
		if not q:
			raise cherrypy.InternalRedirect('/dns')
		
		# Strip the query string and make sure it's a string
		q = str(q).strip()
		
		values['search'] = q
		values['dns_types'] = self.webservice.get_dns_types({ 'min_perms' : str(frontend.perms.READ), 'order_by' : 'name'  })
		
		# Search by MAC if query is a hostname
		if validation.is_fqdn(q):
			host = self.webservice.get_hosts( { 'hostname' : q } )
			if host:
				values['dns'] = self.get_dns( mac=host[0]['mac'] )
		
		if validation.is_ip(q):
			values['dns'] = self.get_dns( address=q )
		elif validation.is_mac(q):
			values['dns'] = self.get_dns( mac=q )
		else:
			if not values.has_key('dns'):
				values['dns'] = self.get_dns( name=q )
				values['dns'] += self.get_dns( content=q )
		
		return self.__template.wrap(leftcontent=self.get_leftnav(), filename='%s/templates/dns.tmpl'%frontend.static_dir, values=values)

