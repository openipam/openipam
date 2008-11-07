import cherrypy

from basepage import BasePage

import framework
from resource.submenu import submenu

class DNS(BasePage):
    '''The DNS class. This includes all pages that are /dns/*'''
    
    def __init__(self):
		BasePage.__init__(self)
		
		# Object for wrapping HTML into the template
		self.__template = framework.Basics("dns")
		
    #-----------------------------------------------------------------
    
    @cherrypy.expose
    def index(self):
        """The DNS page"""

        # Confirm user authentication
        self.check_session()
        
        html = '''
        
        <h1>Manage DNS</h1>
        <div class="message">
        	Under construction.
        </div>
        '''
        
        return self.__template.wrap(html)
        
