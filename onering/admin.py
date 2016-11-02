import os, binascii
from models import Identity, Key
from django import forms
from django.contrib import admin

#--------- ONERING ---------
class IdentityAdmin(admin.ModelAdmin):
    def queryset(self, request):
        return Identity.objects
    class Meta:
        readonly_fields=('public_key')

class KeyAdmin(admin.ModelAdmin):
    readonly_fields = ('pubkey','privkey',)
    def pubkey(self,instance):
        return binascii.hexlify(instance.PublicKey())
    def privkey(self,instance):
        return binascii.hexlify(instance.PrivateKey())
    def queryset(self, request):
        return Key.objects
    class Meta:
          model = Key

class KeyAdminForm(forms.ModelForm):
    class Meta:
          fields = ('parent', 'keyspec', 'identity', 'pubkey', 'privkey')

admin.site.register(Identity, IdentityAdmin)
admin.site.register(Key, KeyAdmin)
