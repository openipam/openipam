import cherrypy
import logging

# class IPAMLogManager( cherrypy._cplogging.LogManager ):
class IPAMLogManager(cherrypy._GlobalLogManager):
    def __init__(
        self, appid=None, logger_root="cherrypy", client_ip_header=None, syslog=False
    ):
        self.client_ip_header = client_ip_header
        cherrypy._cplogging.LogManager.__init__(
            self, appid=appid, logger_root=logger_root
        )
        self.screen = True

    def access(self):
        """Write to the access log."""
        request = cherrypy.request
        remote = request.remote
        response = cherrypy.response
        outheaders = response.headers
        tmpl = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
        client_ip = None
        if self.client_ip_header and self.client_ip_header in request.headers:
            client_ip = request.headers[self.client_ip_header].strip()
        s = tmpl % {
            "h": client_ip or remote.name or remote.ip,
            "l": "-",
            "u": getattr(request, "login", None) or "-",
            "t": self.time(),
            "r": request.request_line,
            "s": response.status.split(" ", 1)[0],
            "b": outheaders.get("Content-Length", "") or "-",
            "f": outheaders.get("referer", ""),
            "a": outheaders.get("user-agent", ""),
        }
        try:
            self.access_log.log(cherrypy._cplogging.logging.INFO, s)
        except:
            self(traceback=True)
