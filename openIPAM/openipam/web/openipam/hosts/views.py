# Create your views here.
from annoying.decorators import render_to

from django.conf import settings
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse
from .forms import SingleHostForm

@render_to('hosts.html')
def index(request):
	return {}

@render_to('hosts.html')
def host(request, host=None):
	"""
	Add/Edit a host's information
	"""
	
	if request.method == 'POST':
		form = SingleHostForm(request.POST)
		if form.is_valid():
			pass
	else:
		form = SingleHostForm()
		
	vals = {
		"title" : host if host is not None else "Add Host",
		"form" : form
	}
	return vals
