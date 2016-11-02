from __future__ import unicode_literals
from django.db import models
from django.conf import settings
import os.path
from Crypto.Hash import SHA256
from key import Keyring, CreateKeyspec, create_keyspec
from datetime import datetime
import binascii
from utils import hasher
import utils
from sentencegenerator import generateSentences
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from signmessage import sign_and_verify
import json

class Identity(models.Model):
    public_key = None
    private_key = None
    paragraph = models.CharField(max_length=800,null=True, blank=True)
    def save_to_blockchain(self,action):
        if settings.TAO_WALLET is None:
            raise ValueError('The Tao Wallet is not configured!')
        rpc_connection = AuthServiceProxy("http://%s:%s@%s"%(settings.TAO_WALLET['rpc_user'], settings.TAO_WALLET['rpc_password'],settings.TAO_WALLET['host'].replace("http://","")))
        pubkey = binascii.hexlify(self.Key("m").PublicKey())
        creator = self.Key("m").TaoAddress()
        if action == "create":
            msg = binascii.hexlify(hasher(pubkey))
            action_data = {
                "action":"create",
                "pubkey":pubkey,
            }
            msg = binascii.hexlify(hasher(json.dumps(action_data)))
            sig = sign_and_verify(self.Key("m").TaoWalletImportFormat(),msg,creator)
            id_data = {
                "type":"identity",
                "version":utils.DATA_VERSION,
                "signature":sig,
                "creator":creator,
                "data":action_data,
                "test":settings.DEBUG,
            }
            app_id = binascii.hexlify(utils.APP_ID)[0:40]
            json_data = json.dumps(id_data) 
            data = rpc_connection.sendtoaddress("TZJozAg1ruapycCicgz31GxvYJ1G1qELV7",0.001,json_data,app_id)
    def create(self,paragraph=None):
        if self.paragraph is None:
            self.paragraph = generateSentences()
        else:
            self.paragraph = paragraph
        self.save_to_blockchain("create")
    def passphrase(self):
        return hasher(self.paragraph)
    def Keyring(self,password=None):
        if (password==None):
            password=self.passphrase()
        return Keyring(password)
    def fingerprint(self,password=None):
        if (password==None):
            password=self.passphrase()
        return binascii.hexlify(self.pubkey(password)[:3] + self.pubkey(password)[-3:])
    def pubkey(self,password=None):
        if (password==None):
            password=self.passphrase()
        return self.Key("m").PublicKey()
    def privkey(self,password=None):
        if (password==None):
            password=self.passphrase()
        return self.Key("m").PrivateKey()
    def Key(self, ks=None, password=None):
        if (password==None):
            password=self.passphrase()
        if ks is None:
            keyspec=Key()
            keyspec = keyspec.create(ks=CreateKeyspec(), identity=self)
            keyspec.save()
        else:
            if ks == "m":
                keyspec = self.Keyring(password).FromKeyspec("m")
            else:
                if ks == "m/0":
                    keyspec = self.Keyring(password).FromKeyspec("m/0")
                else:
                    keyspec = Key.objects.get(keyspec=binascii.hexlify(ks), identity=self)
        return keyspec

def create_ks():
    return create_keyspec()

class Key(models.Model):
    parent = models.ForeignKey("Key",null=True, blank=True)
    keyspec = models.CharField(max_length=800,null=True, blank=True,default=create_ks)
    identity = models.ForeignKey("Identity",null=False, blank=True)
    def save_to_blockchain(self,action):
        if settings.TAO_WALLET is None:
            raise ValueError('The Tao Wallet is not configured!')
        rpc_connection = AuthServiceProxy("http://%s:%s@%s"%(settings.TAO_WALLET['rpc_user'], settings.TAO_WALLET['rpc_password'],settings.TAO_WALLET['host'].replace("http://","")))
        if action=="key":
            msg = binascii.hexlify(hasher(self.get_keyspec()))
            sig = sign_and_verify(self.identity.Key("m").TaoWalletImportFormat(),msg,self.identity.Key("m").TaoAddress())
            key_data = {
                "action":action,
                "keyspec":binascii.hexlify(self.get_keyspec()),
                "address":self.TaoAddress(),
                "signature":sig,
            }
            msg = binascii.hexlify(hasher(json.dumps(key_data)))
            sig = sign_and_verify(self.identity.Key("m").TaoWalletImportFormat(),msg,self.identity.Key("m").TaoAddress())
            final = {
                "type":"identity",
                "version":utils.DATA_VERSION,
                "creator":self.identity.Key("m").TaoAddress(),
                "signature":sig,
                "data":key_data,
                "test":settings.DEBUG,
            }
            app_id = binascii.hexlify(utils.APP_ID)[0:40]
            json_data = json.dumps(final) 
            data = rpc_connection.sendtoaddress("TZJozAg1ruapycCicgz31GxvYJ1G1qELV7",0.001,json_data,app_id)
    def get_keyspec(self):
        return binascii.unhexlify(self.keyspec)
    def set_keyspec(self, ks):
        if ks is None:
            ks = CreateKeyspec()
        self.keyspec = binascii.hexlify(ks)
    def create(self, ks=None, identity = None):
        self.set_keyspec(ks)
        self.identity = identity
        self.save()
        self.save_to_blockchain("key")
        return self
    def __unicode__(self):
       return self.TaoAddress()
    def BitcoinWalletImportFormat(self):
        return self.identity.Keyring(self.identity.passphrase()).FromKeyspec(self.get_keyspec()).BitcoinWalletImportFormat()        
    def TaoWalletImportFormat(self):
        return self.identity.Keyring(self.identity.passphrase()).FromKeyspec(self.get_keyspec()).TaoWalletImportFormat()        
    def Sign(self,message):
        return sign_and_verify(self.TaoWalletImportFormat(), message, self.TaoAddress(), True)
    def Verify(self,signature, message):
        return verify_message(self.TaoAddress(),signature,message)
    def PrivateKey(self):
        return self.identity.Keyring(self.identity.passphrase()).FromKeyspec(self.get_keyspec()).PrivateKey()
    def PublicKey(self):
        return self.identity.Keyring(self.identity.passphrase()).FromKeyspec(self.get_keyspec()).PublicKey()
    def BitcoinAddress(self):
        return self.identity.Keyring(self.identity.passphrase()).FromKeyspec(self.get_keyspec()).BitcoinAddress()
    def TaoAddress(self):
        return self.identity.Keyring(self.identity.passphrase()).FromKeyspec(self.get_keyspec()).TaoAddress()

