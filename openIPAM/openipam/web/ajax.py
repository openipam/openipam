import cherrypy
import datetime
import cjson
try:
    # python3
    import _thread
except ImportError:
    # python2
    import thread as _thread

from .basepage import BasePage
from cherrypy._cptools import XMLRPCController
from openipam.utilities import error, jsonhax


class AjaxTransport(BasePage, XMLRPCController):
    """
	The ajax transport class for allowing Ajax requests to talk to the webservice
	layer through the front end.
	
	This exposes the backend webservices to clients without the need for exposing
	the backend server itself via firewall rules.
	
	You can do nested structures through an Ajax call by:
		data: { 'json' : JSON.stringify(...some JSON object...) },
	If 'json' is specified, all arguments to the function you are calling will be
	the replaced with the value of the 'json' key (after it's decoded from JSON).
	
	Datetime note:
	
	The AjaxTransport exposes the webservice results as JSON. Since JSON does not
	currently have proper support for datetimes, the results of the webservice call
	are serialized (if datetimes) using utilities.jsonhax into a format capable for
	JavaScript. 
	
	So this is a FIXME: when JSON is more date-friendly, don't use utilities.jsonhax
	
	"""

    # -----------------------------------------------------------------
    # 					  PUBLISHED FUNCTIONS
    # -----------------------------------------------------------------

    def __init__(self):

        # FIXME: see above note about datetimes
        # These are all the database columns names that have the potential to be datetimes
        self.__datetime_columns = ("changed", "starts", "ends", "disabled", "expires")

        BasePage.__init__(self)
        XMLRPCController.__init__(self)
        self.__name_lock = _thread.allocate_lock()

        # -----------------------------------------------------------------

    def __getattr__(self, name):
        """
		This function is called when a unknown method is invoked.
		"""

        if name[:5] == "ajax_":
            try:
                self.__name_lock.acquire()
                self.__name = name[5:]
            except:
                self.__name_lock.release()
                raise
            return self.call_wrapper
        raise AttributeError(name)

        # -----------------------------------------------------------------
        # 						EXPOSED FUNCTIONS
        # -----------------------------------------------------------------

    @cherrypy.expose
    def call_wrapper(self, **kw):
        # Confirm user authentication and make sure we have a webservice object

        if not self.__name_lock.locked():
            raise Exception("Somehow, I don't have my __name_lock.  This is very bad.")

        name = self.__name
        del self.__name
        self.__name_lock.release()

        self.check_session()
        function = getattr(self.webservice, name)
        if "json" in kw:
            kw = cjson.decode(kw["json"])

        result = function(kw)

        # Go through the result rows (better be dictionaries)
        if result:
            for row in result:

                # Loop through our self.__datetime_columns and convert those datetime objects
                for column in self.__datetime_columns:

                    if column in row and isinstance(row[column], datetime.datetime):
                        # Wow...ok...
                        # We're on a datetime object, JSON-haxify it to be a JSON string compatible with JavaScript:

                        row[column] = jsonhax.datetime2json(row[column])

        try:
            return cjson.encode(result)
        except Exception as e:
            print(e, result)
            raise

    @cherrypy.expose
    def index(self, *args):
        raise cherrypy.InternalRedirect("/denied")

    @cherrypy.expose
    def default(self, *args):
        raise cherrypy.InternalRedirect("/denied")
        # -----------------------------------------------------------------
