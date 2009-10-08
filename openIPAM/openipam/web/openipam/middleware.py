from django.conf import settings
from django.http import HttpResponseRedirect

class PermissionsMiddleware(object):
	def process_view(self, request, view_func, view_args, view_kwargs):
		assert hasattr(request, 'session'), "The permissions middleware requires session middleware to be installed. Edit your MIDDLEWARE_CLASSES setting to insert 'django.contrib.sessions.middleware.SessionMiddleware'."
		
		# Allow static files to be served without login
		if settings.DEBUG and request.path.startswith(settings.MEDIA_URL):
			return None
		
		# Check for views that have used the login_not_required decorator
		if hasattr(view_func, 'login_not_required') and view_func.login_not_required:
			return None
		
		# Make sure the user is logged in to see anything, otherwise redirect
		if not request.session.has_key('user'):
			return HttpResponseRedirect('%s?next=%s' %(settings.LOGIN_URL, request.path))
			
		return None
	
class WebserviceMiddleware(object):
	pass