from django import forms
from fields import MACAddressFormField, HostnameFormField

class SingleHostForm(forms.Form):
    mac = MACAddressFormField(label="MAC Address")
    hostname = forms.CharField()
    expiration = forms.EmailField()
    owners = forms.BooleanField(required=False)
    hostname = HostnameFormField()
    ip_address = forms.IPAddressField(label="IP Address")
    description = forms.TextInput() 
