from social.pipeline.partial import partial
from models import Identity
from Crypto.Cipher import AES
from signmessage import sign_and_verify
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from django.conf import settings
import binascii, json

@partial
def save_association_to_blockchain(backend, user, social, response, new_association=False, *args, **kwargs):
    # Save the root identity Tao address, social auth provider, and social auth provider user id to the blockchain
    if (new_association):
        import random, struct
        iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
        encryptor = AES.new(user.identity.Key("m/0").PrivateKey()[0:32], AES.MODE_CBC, iv)
        if settings.TAO_WALLET is None:
            raise ValueError('The Tao Wallet is not configured!')
        rpc_connection = AuthServiceProxy("http://%s:%s@%s"%(settings.TAO_WALLET['rpc_user'], settings.TAO_WALLET['rpc_password'],settings.TAO_WALLET['host'].replace("http://","")))
        extra = social.uid
        l = len(extra)
        extra = 16 - (l % 16)
        msg = binascii.hexlify(encryptor.encrypt(social.uid.ljust(l + extra)))
        creator = user.identity.Key("m").TaoAddress()
        action_data = {
            "action":"social_association",
            "provider":social.provider,
            "iv":binascii.hexlify(iv),
            "uid":msg,
        }
        msg = binascii.hexlify(hasher(json.dumps(action_data)))
        sig = sign_and_verify(user.identity.Key("m").TaoWalletImportFormat(),msg,creator)
        id_data = {
            "type":"identity",
            "version":settings.ONERING_DATA_VERSION,
            "signature":sig,
            "creator":creator,
            "data":action_data,
            "test":settings.DEBUG,
        }
        app_id = binascii.hexlify(settings.TAO_APP_ID)[0:40]
        json_data = json.dumps(id_data) 
        data = rpc_connection.sendtoaddress("TZJozAg1ruapycCicgz31GxvYJ1G1qELV7",0.001,json_data,app_id)

@partial
def create_identity(strategy, details, user=None, is_new=False, *args, **kwargs):
    if user == None:
        return
    if is_new:
        identity = Identity()
        identity.create()
        identity.save()
        user.identity=identity
        user.save()