"""

Some miscellaneous resources for the front-end openIPAM interface

"""

import cherrypy

import os

from openipam.config import frontend


def redirect_to_referer():
    """
	Raises a cherrypy.HTTPRedirect the referrering page
	
	And, yes, it's spelled 'referer' ...
	"""

    referer = "/default"
    if "Referer" in cherrypy.request.headers:
        referer = cherrypy.request.headers["Referer"]
        if referer[:4] != "http":
            raise Exception("This is unexpected... Referer is not http: '%s'" % referer)
        raise cherrypy.HTTPRedirect(referer)
    redirect("/default")


def redirect(path):
    if "http://" == path[:7] or "https://" == path[:8]:
        url = path
    else:
        base = cherrypy.request.base
        if frontend.proxied:
            base = frontend.proxy_base
        url = os.path.join(base, path)
    if "Referer" in cherrypy.request.headers:
        referer = cherrypy.request.headers["Referer"]
        browser_url = cherrypy.request.base + cherrypy.request.path_info
        if cherrypy.request.query_string:
            browser_url = "%s?%s" % (browser_url, cherrypy.request.query_string)
        if url == browser_url:
            raise Exception(
                "Trying to redirect to self!! %s to %s" % (browser_url, referer)
            )
    print(url)
    raise cherrypy.HTTPRedirect(url)
