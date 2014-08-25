import cherrypy
from local_settings import config

from basepage import BasePage

import framework
from resource.submenu import submenu

class Domains(BasePage):
    '''The Domains class. This includes all pages that are /domains/*'''
    
    def __init__(self):
		BasePage.__init__(self)
		
		# Object for wrapping HTML into the template
		self.__template = framework.Basics("domains")
		
    #-----------------------------------------------------------------
    #                      PUBLISHED FUNCTIONS
    #-----------------------------------------------------------------

    def leftnav_actions(self, current=None):
        '''Returns the html for actions in the leftnav
        @param current: a string of the current action'''
        
        selected = None
        counter = 0

        actions = ('Add Domain',)
        action_links = ('/dns/add',)
        
        # Run through our actions list and highlight the currently selected action
        for action in actions:
            if action == current:
                selected = counter
            counter += 1
        
        return submenu(actions, action_links, "Actions", selected)
    
    #-----------------------------------------------------------------
    
    def domain_form(self, action_string="Add", did=0):
        '''The domain form for adding and editing domains
        @param action: the POST action URL
        @param action_string: "Add" by default, should be "Update" otherwise
        @param gid: If updating, the DB group id. Gid is 0 if new record'''
        
        domain = {}
        domain['name'] = ""
        domain['master'] = ""
        domain['type'] = ""
        
        # Get the domain info from the database if editing
        if did != 0:
            filter = { 'did' : did }
            domain = self.webservice.get_domain(filter)[0]
            
        form = '''<form action="/dns/process_domain" method="post" class="form">
                <div id="element">
                    <div id="label">Domain name*:</div>
                    <div id="value"><input type="text" class="text" name="name" value="''' + domain['name'] + '''" /></div>
                </div>
                <div id="element">
                    <div id="label">Master:</div>
                    <div id="value"><input type="text" class="text" name="master" value="''' + domain['master'] + '''" /></div>
                </div>
                <div id="element">
                    <div id="label">Type:</div>
                    <div id="value"><input type="text" class="text" name="type" value="''' + domain['type'] + '''" /></div>
                </div>
                
                <input type="hidden" name="did" value="''' + str(did) + '''" />
                
                <div class="submit">
                    <input type="submit" class="button" value="''' + action_string + ''' Domain">
                </div>
                
            </form>'''
            
        return form

    #-----------------------------------------------------------------
    #                        EXPOSED FUNCTIONS
    #-----------------------------------------------------------------
    
    @cherrypy.expose
    def index(self):
        """The domains page"""

        # Confirm user authentication
        self.check_session()
        
        leftnav = str(self.leftnav_actions())
        
        
        # The jQuery to make an Ajax request for delete
        jquery = '''<script type="text/javascript">
                        function delGroupConfirm( gid ){
                            $("#del" + gid)
                                .after('<span id="confirm'+gid+'">Are you sure? <a href="javascript:;" onclick="delGroup('+gid+'); return false;">Yes</a> / <a href="javascript:;" onclick="restoreDelGroup('+gid+');">No</a></span>')
                                .hide(); 
                        };
                        
                        function restoreDelGroup( gid ) {
                            $("#confirm"+gid).remove();
                            $("#del"+gid).show();
                        };
                        
                        function delGroup( gid ){
                            $.ajax({
                                type: "GET",
                                url: "/ajax/ajax_del_group/"+gid,
                                success: function() {
                                        $("#group" + gid).remove();
                                    }
                            });
                        };
                    </script>
                    '''
        
        # The template HTML for every entry
        item_template = '''<tr class="info" id="group%(id)s">
                            <td>%(name)s</td>
                            <td>%(master)s</td>
                            <td>%(type)s</td>
                        </tr>
                        '''
#                            <td class="actions">
#                                <a href="/admin/groups/edit/?gid=%(id)s">Edit</a> |
#                                <a href="javascript:;" id="del%(id)s" onclick="delDomainConfirm(%(id)s); return false;">Delete</a> |
#                                <a href="/admin/groups/view/?gid=%(id)s">Members</a>
#                            </td>

        #/admin/groups/delete/?gid=%(id)s
        
        # Get the DNS resource record types from the database
        domains = self.webservice.get_domains()
        
        # Go through the query and make the table HTML using the template
        domains_html = ''
        for domain in domains:
            mapping = {
                       "id" : domain['id'],
                       "name" : domain['name'],
                       "master" : domain['master'],
                       "type" : domain['type'],
                       }
            domains_html += item_template % (mapping)
        
        # Combine all the parts into the table
        info = '''
                <table class="infoTable">
                    <thead>
                        <tr>
                            <th width="25%">Domain Name</th>
                            <th>Master</th>
                            <th>Type</th>
                        </tr>
                    </thead>
                    <tbody>
                    ''' + domains_html + '''
                    </tbody>
                </table>
                '''
        
        maincontent = '''<h1>Domains</h1>''' + info + jquery
        
        return self.__template.wrap(maincontent, leftnav)
    
    #-----------------------------------------------------------------

    @cherrypy.expose
    def add(self):
        '''The form to add a group'''
        
        # Confirm user authentication
        self.check_session()
        
        leftnav = str(self.leftnav_actions("Add Domain"))
        maincontent = '<h1>Add Domain</h1>' + self.domain_form()
        
        return self.__template.wrap(maincontent, leftnav)
    
    #-----------------------------------------------------------------

    @cherrypy.expose
    def edit(self, did):
        '''The form to edit a domain'''
        
        # Confirm user authentication
        self.check_session()
        
        leftnav = str(self.leftnav_actions())
        maincontent = '<h1>Edit Domain</h1>' + self.domain_form("Edit", did)
        
        return self.__template.wrap(maincontent, leftnav)
    
    #-----------------------------------------------------------------

    @cherrypy.expose
    def process_domain(self, **kw):
        '''Process the domain add or edit form and do the DB transactions
        @param kw: a dictionary containing name, description and did (did=0 if adding new record)
        '''

        if int(kw['did']) == 0:
            # We're adding a new domain
            try:
                args = {
                        'name' : kw['name'],
                        'master' : kw['master'],
                        'type' : kw['type']
                        }
                self.webservice.add_domain(args)
            except:
                raise Exception("Could not add domain.")
        else:
            # We're updating a domain
            try:
                args = {
                        'did' : kw['did'],
                        'name' : kw['name'],
                        'master' : kw['master'],
                        'type' : kw['type']
                        }
                self.webservice.edit_domain(args)
            except:
                raise Exception("Could not update domain.")
            
        raise cherrypy.InternalRedirect("/dns")
    
    #-----------------------------------------------------------------