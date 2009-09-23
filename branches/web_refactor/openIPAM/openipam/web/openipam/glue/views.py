# Create your views here.

from annoying.decorators import render_to

from django.conf import settings
from django.http import HttpResponseRedirect
from django.contrib.auth.decorators import login_required

@login_required
@render_to('index.html')
def index(request):
	return {}