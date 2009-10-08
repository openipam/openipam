import re

from django.utils.translation import ugettext_lazy as _
from django.forms import fields
from django.db import models

#MAC_RE = r'^([0-9a-fA-F]{2}([:-]?|$)){6}$'
MAC_RE = r'^[0-9a-fA-F][0-9a-fA-F][:\-.]?[0-9a-fA-F][0-9a-fA-F][:\-.]?[0-9a-fA-F][0-9a-fA-F][:\-.]?[0-9a-fA-F][0-9a-fA-F][:\-.]?[0-9a-fA-F][0-9a-fA-F][:\-.]?[0-9a-fA-F][0-9a-fA-F]$'
mac_re = re.compile(MAC_RE)

class MACAddressFormField(fields.RegexField):
    default_error_messages = {
        'invalid': _(u'Enter a valid MAC address.'),
    }

    def __init__(self, *args, **kwargs):
        super(MACAddressFormField, self).__init__(mac_re, *args, **kwargs)

HOSTNAME_RE = r'^([0-9A-Za-z]+\.[0-9A-Za-z]+|[0-9A-Za-z]+[\-0-9A-Za-z\.]*[0-9A-Za-z])$'
hostname_re = re.compile(HOSTNAME_RE)

class HostnameFormField(fields.RegexField):
    default_error_messages = {
        'invalid': _(u'Enter a valid hostname.'),
    }

    def __init__(self, *args, **kwargs):
        super(HostnameFormField, self).__init__(hostname_re, *args, **kwargs)


class MACAddressField(models.Field):
    empty_strings_allowed = False
    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = 17
        super(MACAddressField, self).__init__(*args, **kwargs)

    def get_internal_type(self):
        return "CharField"

    def formfield(self, **kwargs):
        defaults = {'form_class': MACAddressFormField}
        defaults.update(kwargs)
        return super(MACAddressField, self).formfield(**defaults)
