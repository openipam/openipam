# Create your views here.

from annoying.decorators import render_to

from django.conf import settings
from django.http import HttpResponseRedirect
from decorators.permissions import login_not_required

@login_not_required
@render_to('login.html')
def login(request, logout=False):
	if logout:
		del request.session['user']
		
	if request.method == "POST":
		request.session['user'] = ''
		
		if request.GET.has_key('next'):
			return HttpResponseRedirect(request.GET['next'])
		return HttpResponseRedirect("/")
	
	
	return {}

@render_to('base.html')
def index(request):
	return {}