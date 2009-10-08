from django.conf.urls.defaults import *
from django.conf import settings

urlpatterns = patterns('',
	url(r'^$', 'glue.views.index', name='index'),
	url(r'^hosts/$', 'hosts.views.index', name='hosts'),
	url(r'^hosts/add/$', 'hosts.views.host', name='add_host'),
	url(r'^hosts/edit/(?P<host>.*)$', 'hosts.views.host', name='edit_host'),
	
	# Login/Logout urls
	url(r'^login/$', 'glue.views.login', name='login'),
	url(r'^logout/$', 'glue.views.login', { 'logout' : True }, name='logout'),
)

# Only serve static files in development
if settings.DEBUG:
	urlpatterns += patterns('',
		(r'^static/(?P<path>.*)$', 'django.views.static.serve', {'document_root': settings.MEDIA_ROOT, 'show_indexes': True }),
	)