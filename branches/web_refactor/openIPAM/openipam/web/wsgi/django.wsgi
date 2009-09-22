import os, sys
import django.core.handlers.wsgi

project_root = os.sep.join(__file__.split(os.sep)[:-2])
project_dir = '%s/openipam/' % project_root
if project_root not in sys.path: sys.path.append(project_root)
if project_dir not in sys.path: sys.path.append(project_dir)

os.environ['DJANGO_SETTINGS_MODULE'] = 'openipam.settings'

application = django.core.handlers.wsgi.WSGIHandler()
