# Create your views here.

from annoying.decorators import render_to

from django.conf import settings
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse

from decorators import login_not_required

@login_not_required
@render_to('login.html')
def login(request, logout=False):
	if logout:
		if request.session.has_key('user'):
			del request.session['user']
		
	if request.method == "POST":
		request.session['user'] = ''
		
		if request.GET.has_key('next'):
			return HttpResponseRedirect(request.GET['next'])
		return HttpResponseRedirect("/")
	
	return {}

def index(request):
	return HttpResponseRedirect(reverse('hosts'))
