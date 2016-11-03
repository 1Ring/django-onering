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
import json, base64
from io import BytesIO
import pickle

def commit_object(obj_type,obj,iden):
    data = BytesIO()
    creator = iden.Key("m").TaoAddress()
    pickle.dump(obj,data)
    enc = iden.Key("m").Encrypt(data.getvalue())
    msg = binascii.hexlify(hasher(enc))
    sig = iden.Key("m").Sign(msg)
    if iden.Key("m").Verify(sig,msg):
        id_data = {
            "data":base64.b64encode(enc),
            "test":settings.DEBUG,
            "version":utils.DATA_VERSION,
            "signature":sig,
            "creator":creator,
            "object":obj_type,
        }
        json_data = json.dumps(id_data) 
        try:
            rpc_connection = AuthServiceProxy("http://%s:%s@%s"%(settings.TAO_WALLET['rpc_user'], settings.TAO_WALLET['rpc_password'],settings.TAO_WALLET['host'].replace("http://","")))
        except:
            raise Exception("Connection to wallet failed.")
        try:
            data = rpc_connection.sendtoaddress("TZJozAg1ruapycCicgz31GxvYJ1G1qELV7",0.001,json_data,binascii.hexlify(utils.APP_ID)[0:40])
        except:
            raise Exception ("RPC failed.")
    else:
        raise Exception("Signature failed.")

class Identity(models.Model):
    paragraph = models.CharField(max_length=800,null=True, blank=True)
    def save_to_blockchain(self):
        if settings.TAO_WALLET is None:
            raise ValueError('The Tao Wallet is not configured!')
        commit_object("identity",self,self)
    def create(self,paragraph=None):
        if self.paragraph is None:
            self.paragraph = generateSentences()
        else:
            self.paragraph = paragraph
        self.save_to_blockchain()
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
            raise Exception('The Tao Wallet is not configured!')
        commit_object("key",self,self)
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
    def Encrypt(self):
        return self.identity.Keyring(self.identity.passphrase()).FromKeyspec(self.get_keyspec()).Encrypt(msg)        
    def BitcoinWalletImportFormat(self):
        return self.identity.Keyring(self.identity.passphrase()).FromKeyspec(self.get_keyspec()).BitcoinWalletImportFormat()        
    def TaoWalletImportFormat(self):
        return self.identity.Keyring(self.identity.passphrase()).FromKeyspec(self.get_keyspec()).TaoWalletImportFormat()        
    def Sign(self,message):
        return self.identity.Keyring(self.identity.passphrase()).FromKeyspec(self.get_keyspec()).Sign(message)
    def Verify(self,signature, message):
        return self.identity.Keyring(self.identity.passphrase()).FromKeyspec(self.get_keyspec()).Verify(signature,message,self.TaoAddres())
    def PrivateKey(self):
        return self.identity.Keyring(self.identity.passphrase()).FromKeyspec(self.get_keyspec()).PrivateKey()
    def PublicKey(self):
        return self.identity.Keyring(self.identity.passphrase()).FromKeyspec(self.get_keyspec()).PublicKey()
    def BitcoinAddress(self):
        return self.identity.Keyring(self.identity.passphrase()).FromKeyspec(self.get_keyspec()).BitcoinAddress()
    def TaoAddress(self):
        return self.identity.Keyring(self.identity.passphrase()).FromKeyspec(self.get_keyspec()).TaoAddress()

