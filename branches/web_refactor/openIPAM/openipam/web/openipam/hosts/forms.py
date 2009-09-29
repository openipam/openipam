from django import forms
from fields import MACAddressFormField

class SingleHostForm(forms.Form):
    mac = MACAddressFormField(max_length=17)
    hostname = forms.CharField()
    expiration = forms.EmailField()
    owners = forms.BooleanField(required=False)
    hostname = forms.CharField()
    description = forms.TextInput() 
