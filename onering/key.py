#!/usr/bin/env python
#
# Copyright 2014 Corgan Labs
# Copyright 2015 Alternative Systems All Rights Reserved
#
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions are met:
#
# *   Redistributions of source code must retain the above copyright notice, 
#       this list of conditions and the following disclaimer. 
# *   Redistributions in binary form must reproduce the above copyright notice, 
#       this list of conditions and the following disclaimer in the 
#       documentation and/or other materials provided with the distribution. 
# *   Neither the name of the Alternative Systems LLC nor the names of its 
#       contributors may be used to endorse or promote products derived from 
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
# ARE DISCLAIMED. IN NO EVENT SHALL THE ALTSYSTEM OR CONTRIBUTORS BE LIABLE FOR 
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE 
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# EXPORT LAWS: THIS LICENSE ADDS NO RESTRICTIONS TO THE EXPORT LAWS OF YOUR 
# JURISDICTION. It is licensee's responsibility to comply with any export 
# regulations applicable in licensee's jurisdiction. Under CURRENT (Dec 2015) 
# U.S. export regulations this software is eligible for export from the U.S. 
# and can be downloaded by or otherwise exported or reexported worldwide EXCEPT 
# to U.S. embargoed destinations which include Cuba, Iraq, Libya, North Korea, 
# Iran, Syria, Sudan, Afghanistan and any other country to which the U.S. has 
# embargoed goods and services.
#
# The ECDSA version of ElGamal was originally conceived at https://github.com/jackjack-jj/jeeq
#
import os
import binascii
import hmac
import hashlib
import ecdsa

import struct
import Base58, base64
import secp256k1
from secp256k1 import ALL_FLAGS

from coins import COINS

from hashlib import sha256
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import int_to_string, string_to_int
from ecdsa.numbertheory import square_root_mod_prime as sqrt_mod
import random
import sqlite3 as db
import utils
from Crypto.Cipher import AES
from utils import hasher
from coins import COINS
import zlib

_HARDEN    = 0x80000000 # choose from hardened set of child keys

CURVE_GEN       = ecdsa.ecdsa.generator_secp256k1
CURVE_ORDER     = CURVE_GEN.order()
FIELD_ORDER     = SECP256k1.curve.p()
INFINITY        = ecdsa.ellipticcurve.INFINITY
CONFIG  =   {
                'Version': 10001,
                'EntropyBits': 128
            } 
oneringversion='0.0.1'
def create_keyspec():
    return binascii.hexlify(CreateKeyspec())
def varint(size):
    # Variable length integer encoding:
    # https://en.bitcoin.it/wiki/Protocol_documentation
    if size < 0xFD:
        return struct.pack(b'<B', size)
    elif size <= 0xFFFF:
        return b'\xFD' + struct.pack(b'<H', size)
    elif size <= 0xFFFFFFFF:
        return b'\xFE' + struct.pack(b'<I', size)
    else:
        return b'\xFF' + struct.pack(b'<Q', size)
    
class Key(object):
    # Normal class initializer
    def __init__(self, secret, chain, depth, index, fpr, coin='1Ring', testnet=False, public=False):
        """
        Create a public or private Key using key material and chain code.

        secret   This is the source material to generate the keypair, either a
                 32-byte string representation of a private key, or the ECDSA
                 library object representing a public key.

        chain    This is a 32-byte string representation of the chain code

        depth    Child depth; parent increments its own by one when assigning this

        index    Child index

        fpr      Parent fingerprint

        public   If true, this keypair will only contain a public key and can only create
                 a public key chain.
        """
        self.coin = coin
        self.public = public
        if public is False:
            self.k = ecdsa.SigningKey.from_string(secret, curve=SECP256k1)
            self.K = self.k.get_verifying_key()
        else:
            self.k = None
            self.K = secret

        self.C = chain
        self.depth = depth
        self.index = index
        self.parent_fpr = fpr
        self.coin = coin
        self.testnet = testnet
        if self.testnet:
            self.network = 'test'
        else:
            self.network = 'main'
        self.msgprefix=b'Tao Signed Message:\n'

    def negative_self(self, point):
        return ecdsa.ellipticcurve.Point( point.curve(), point.x(), -point.y(), point.order() )

    def ser( self, point, comp=True ):
        x = point.x()
        y = point.y()
        if comp:
            return ( ('%02x'%(2+(y&1)))+('%064x'%x) ).decode('hex')
        return ( '04'+('%064x'%x)+('%064x'%y) ).decode('hex')
    def Verify(self, base64sig, msg, address=None, ctx=None):
        if address is None:
            address=self.TaoAddress()
        if len(base64sig) != 88:
            raise Exception("Invalid base64 signature length")

        msg = msg.encode('utf8')
        fullmsg = (varint(len(self.msgprefix)) + self.msgprefix +
                   varint(len(msg)) + msg)
        hmsg = sha256(sha256(fullmsg).digest()).digest()

        sigbytes = base64.b64decode(base64sig)
        if len(sigbytes) != 65:
            raise Exception("Invalid signature length")

        compressed = (ord(sigbytes[0:1]) - 27) & 4 != 0
        rec_id = (ord(sigbytes[0:1]) - 27) & 3

        p = secp256k1.PublicKey(ctx=ctx, flags=ALL_FLAGS)
        sig = p.ecdsa_recoverable_deserialize(sigbytes[1:], rec_id)

        # Recover the ECDSA public key.
        recpub = p.ecdsa_recover(hmsg, sig, raw=True)
        pubser = secp256k1.PublicKey(recpub, ctx=ctx).serialize(compressed=compressed)

        vh160=COINS["Tao"]['main']['prefix'].decode('hex')+hashlib.new('ripemd160', sha256(pubser).digest()).digest()
        addr = Base58.check_encode(vh160)
        return addr == address

    def Sign(self, msg, compressed=True):
        privkey = secp256k1.PrivateKey()
        privkey.set_raw_privkey(self.PrivateKey())
        msg = msg.encode('utf8')
        fullmsg = (varint(len(self.msgprefix)) + self.msgprefix +
                   varint(len(msg)) + msg)
        hmsg = sha256(sha256(fullmsg).digest()).digest()

        rawsig = privkey.ecdsa_sign_recoverable(hmsg, raw=True)
        sigbytes, recid = privkey.ecdsa_recoverable_serialize(rawsig)

        meta = 27 + recid
        if compressed:
            meta += 4

        res = base64.b64encode(chr(meta).encode('utf8') + sigbytes)
        return res

    def RecoverPubkey(self, message,signature):
        if len(signature) != 65:
            raise Exception("Invalid signature length")
        empty = secp256k1.PublicKey(flags=ALL_FLAGS)
        sig = p.ecdsa_recoverable_deserialize(sigbytes[1:], rec_id)

        pubkey = empty.schnorr_recover(message,signature)
        return secp256k1.PublicKey(pubkey)

    def ECC_YfromX(self,x,curved=SECP256k1.curve, odd=True):
        _p = curved.p()
        _a = curved.a()
        _b = curved.b()
        for offset in range(128):
            Mx=x+offset
            My2 = pow(Mx, 3, _p) + _a * pow(Mx, 2, _p) + _b % _p
            My = pow(My2, (_p+1)/4, _p )

            if curved.contains_point(Mx,My):
                if odd == bool(My&1):
                    return [My,offset]
                return [_p-My,offset]
        raise Exception('ECC_YfromX: No Y found')

    def private_header(self,msg,v):
        assert v<1, "Can't write version %d private header"%v
        r=''
        if v==0:
            r+=('%08x'%len(msg)).decode('hex')
            r+=sha256(msg).digest()[:2]
        return ('%02x'%v).decode('hex') + ('%04x'%len(r)).decode('hex') + r

    def public_header(self,pubkey,v):
        assert v<1, "Can't write version %d public header"%v
        r=''
        if v==0:
            r=sha256(pubkey).digest()[:2]
        return '\x6a\x6a' + ('%02x'%v).decode('hex') + ('%04x'%len(r)).decode('hex') + r

    def Encrypt(self, m,curved=SECP256k1.curve,generator=CURVE_GEN):
        # ElGamal encryption for ECDSA key pairs
        pubkey = self.CompressedPublicKey()
        r=''
        msg = self.private_header(m,0)+m
        msg = msg+('\x00'*( 32-(len(msg)%32) ))
        msgs = chunks(msg,32)

        _r  = CURVE_ORDER

        P = generator
        if len(pubkey)==33: #compressed
            pk = ecdsa.ellipticcurve.Point( curved, string_to_int(pubkey[1:33]), self.ECC_YfromX(string_to_int(pubkey[1:33]), curved, pubkey[0]=='\x03')[0], _r )
        else:
            pk = ecdsa.ellipticcurve.Point( curved, string_to_int(pubkey[1:33]), string_to_int(pubkey[33:65]), _r )

        for g in msgs:
            rand=( ( '%013x' % long(random.random() * 0xfffffffffffff) )*5 )

            n = long(rand,16) >> 4
            Mx = string_to_int(g)
            My,xoffset=self.ECC_YfromX(Mx, curved)
            M = ecdsa.ellipticcurve.Point( curved, Mx+xoffset, My, _r )

            T = P*n
            U = pk*n + M

            toadd = self.ser(T) + self.ser(U)
            toadd = chr(ord(toadd[0])-2+2*xoffset)+toadd[1:]
            r+=toadd
        return zlib.compress(base64.b64encode(self.public_header(pubkey,0) + r))

    def pointSerToPoint(self,Aser, curved=SECP256k1.curve, generator=CURVE_GEN):
        _r  = generator.order()
        assert Aser[0] in ['\x02','\x03','\x04']
        if Aser[0] == '\x04':
            return ecdsa.ellipticcurve.Point( curved, string_to_int(Aser[1:33]), string_to_int(Aser[33:]), _r )
        Mx = string_to_int(Aser[1:])
        return ecdsa.ellipticcurve.Point( curved, Mx, self.ECC_YfromX(Mx, curved, Aser[0]=='\x03')[0], _r )

    def Decrypt(self,enc, curved=SECP256k1.curve, verbose=False, generator=CURVE_GEN):
        # ElGamal dencryption for ECDSA key pairs
        P = generator
        pvk=string_to_int(self.PrivateKey())
        pubkeys = [self.ser((P*pvk),True), self.ser((P*pvk),False)]
        enc = base64.b64decode(zlib.decompress(enc))

        assert enc[:2]=='\x6a\x6a'      

        phv = string_to_int(enc[2])
        assert phv==0, "Can't read version %d public header"%phv
        hs = string_to_int(enc[3:5])
        public_header=enc[5:5+hs]
        checksum_pubkey=public_header[:2]

        address=filter(lambda x:sha256(x).digest()[:2]==checksum_pubkey, pubkeys)
        assert len(address)>0, 'Bad private key'
        address=address[0]
        enc=enc[5+hs:]


        r = ''
        for Tser,User in map(lambda x:[x[:33],x[33:]], chunks(enc,66)):
            ots = ord(Tser[0])
            xoffset = ots>>1
            Tser = chr(2+(ots&1))+Tser[1:]
            T = self.pointSerToPoint(Tser,curved,generator)
            U = self.pointSerToPoint(User,curved,generator)

            V = T*pvk
            Mcalc = U+(self.negative_self(V))
            r += ('%064x'%(Mcalc.x()-xoffset)).decode('hex')


        pvhv = string_to_int(r[0])
        assert pvhv==0, "Can't read version %d private header"%pvhv
        phs = string_to_int(r[1:3])
        private_header = r[3:3+phs]
        size = string_to_int(private_header[:4])
        checksum = private_header[4:6]
        r = r[3+phs:]

        msg = r[:size]
        hashmsg = sha256(msg).digest()[:2]
        checksumok = hashmsg==checksum        

        return [msg, checksumok, address]

    # Static initializers to create from entropy or external formats
    #
    @staticmethod
    def fromEntropy(entropy, coin='1Ring', testnet=False, public=False):
        "Create a Key using supplied entropy >= CONFIG['EntropyBits']"
        if entropy == None:
            entropy = os.urandom(CONFIG['EntropyBits']/8) 
        if not len(entropy) >= CONFIG['EntropyBits']/8:
            raise ValueError("Initial entropy %i must be at least %i bits" %
                                (len(entropy), CONFIG['EntropyBits']))
        I = hmac.new(coin.capitalize() + " seed", entropy, hashlib.sha512).digest()
        Il, Ir = I[:32], I[32:]
        # FIXME test Il for 0 or less than SECP256k1 prime field order
        assert Il > 0

        key = Key(secret=Il, chain=Ir, depth=0, index=0, fpr='\0\0\0\0', coin=coin, testnet=testnet, public=False)
        if public:
            key.SetPublic()
        return key

    @staticmethod
    def fromExtendedKey(xkey, coin='1Ring', testnet=False, public=False):
        """
        Create a Key by importing from extended private or public key string

        If public is True, return a public-only key regardless of input type.
        """
        if coin == 'ethereum' or coin == 'expanse':
            raw = xkey
        else:
            # Sanity checks
            raw = Base58.check_decode(xkey)
            if len(raw) != 78:
                raise ValueError("extended key format wrong length")

        # Verify address version/type
        version = raw[:4]
        if testnet:
            network = "test"
        else:
            network = "main"
        if coin == 'ethereum' or coin == 'expanse':
            keytype = COINS[coin][network]['xkeyprv']
        else:
            if version == COINS[coin][network]['private'].decode('hex'):
                keytype = COINS[coin][network]['xkeyprv']
            elif version == COINS[coin][network]['public'].decode('hex'):
                keytype = COINS[coin][network]['xkeypub']
            else:
                raise ValueError("unknown extended key version")

        # Extract remaining fields
        depth = ord(raw[4])
        fpr = raw[5:9]
        child = struct.unpack(">L", raw[9:13])[0]
        chain = raw[13:45]
        secret = raw[45:78]

        # Extract private key or public key point
        if keytype == COINS[coin][network]['xkeyprv']:
            secret = secret[1:]
        else:
            # Recover public curve point from compressed key
            lsb = ord(secret[0]) & 1
            x = string_to_int(secret[1:])
            ys = (x**3+7) % FIELD_ORDER # y^2 = x^3 + 7 mod p
            y = sqrt_mod(ys, FIELD_ORDER)
            if y & 1 != lsb:
                y = FIELD_ORDER-y
            point = ecdsa.ellipticcurve.Point(SECP256k1.curve, x, y)
            secret = ecdsa.VerifyingKey.from_public_point(point, curve=SECP256k1)

        is_pubkey = (keytype == COINS[coin][network]['xkeypub'])
        key = Key(secret=secret, chain=chain, depth=depth, index=child, fpr=fpr, coin=coin, testnet=testnet, public=is_pubkey)
        if not is_pubkey and public:
            key = key.SetPublic()
        return key

    # Internal methods not intended to be called externally
    #
    def hmac(self, data):
        """
        Calculate the HMAC-SHA512 of input data using the chain code as key.

        Returns a tuple of the left and right halves of the HMAC
        """         
        I = hmac.new(self.C, data, hashlib.sha512).digest()
        return (I[:32], I[32:])

    def CKDpriv(self, i):
        """
        Create a child key of index 'i'.

        If the most significant bit of 'i' is set, then select from the
        hardened key set, otherwise, select a regular child key.

        Returns a BIP32Key constructed with the child key parameters,
        or None if i index would result in an invalid key.
        """
        # Index as bytes, BE
        i_str = struct.pack(">L", i)

        # Data to HMAC
        if i & _HARDEN:
            data = b'\0' + self.k.to_string() + i_str
        else:
            data = self.PublicKey() + i_str
        # Get HMAC of data
        (Il, Ir) = self.hmac(data)

        # Construct new key material from Il and current private key
        Il_int = string_to_int(Il)
        if Il_int > CURVE_ORDER:
            return None
        pvt_int = string_to_int(self.k.to_string())
        k_int = (Il_int + pvt_int) % CURVE_ORDER
        if (k_int == 0):
            return None
        secret = (b'\0'*32 + int_to_string(k_int))[-32:]
        
        # Construct and return a new Key
        return Key(secret=secret, chain=Ir, depth=self.depth+1, index=i, fpr=self.Fingerprint(), coin=self.coin, testnet=self.testnet, public=False)

    def CKDpub(self, i):
        """
        Create a publicly derived child key of index 'i'.

        If the most significant bit of 'i' is set, this is
        an error.

        Returns a Key constructed with the child key parameters,
        or None if index would result in invalid key.
        """

        if i & _HARDEN:
            raise Exception("Cannot create a hardened child key using public child derivation")

        # Data to HMAC.  Same as CKDpriv() for public child key.
        data = self.PublicKey() + struct.pack(">L", i)

        # Get HMAC of data
        (Il, Ir) = self.hmac(data)

        # Construct curve point Il*G+K
        Il_int = string_to_int(Il)
        if Il_int >= CURVE_ORDER:
            return None
        point = Il_int*CURVE_GEN + self.K.pubkey.point
        if point == INFINITY:
            return None

        # Retrieve public key based on curve point
        K_i = ecdsa.VerifyingKey.from_public_point(point, curve=SECP256k1)

        # Construct and return a new Key
        return Key(secret=K_i, chain=Ir, depth=self.depth, index=i, fpr=self.Fingerprint(), coin=self.coin, testnet=self.testnet, public=True)

    # Public methods
    #
    def ChildKey(self, i):
        """
        Create and return a child key of this one at index 'i'.

        The index 'i' should be summed with _HARDEN to indicate
        to use the private derivation algorithm.
        """
        if self.public is False:
            return self.CKDpriv(i)
        else:
            return self.CKDpub(i)

    def SetPublic(self):
        "Convert a private Key into a public one"
        self.k = None
        self.public = True

    def PrivateKey(self):
        "Return private key as string"
        if self.public:
            raise Exception("Publicly derived deterministic keys have no private half")
        else:
            return self.k.to_string()

    def PublicKey(self):
        return self.K.to_string()

    def CompressedPublicKey(self):
        "Return compressed public key encoding"
        if self.K.pubkey.point.y() & 1:
            ck = b'\3'+int_to_string(self.K.pubkey.point.x())
        else:
            ck = b'\2'+int_to_string(self.K.pubkey.point.x())
        return ck

    def ChainCode(self):
        "Return chain code as string"
        return self.C

    def Identifier(self):
        "Return key identifier as string"
        cK = self.CompressedPublicKey()
        return hashlib.new('ripemd160', sha256(cK).digest()).digest()

    def Fingerprint(self):
        "Return key fingerprint as string"
        return self.Identifier()[:4]

    def Address(self):
        "Return compressed public key address"
        if self.coin=='ethereum' or self.coin=='expanse':
            import lib.python_sha3
            return lib.python_sha3.sha3_256(self.CompressedPublicKey()).hexdigest()[-40:]
        else:
            vh160 = COINS[self.coin][self.network]['prefix'].decode('hex')+self.Identifier()
            return Base58.check_encode(vh160)

    def BitcoinAddress(self):
        vh160 = COINS["bitcoin"]['main']['prefix'].decode('hex')+self.Identifier()
        return Base58.check_encode(vh160)

    def TaoAddress(self):
        vh160 = COINS["Tao"]['main']['prefix'].decode('hex')+self.Identifier()
        return Base58.check_encode(vh160)

    def TaoWalletImportFormat(self):
        "Returns private key encoded for wallet import"
        if self.public:
            raise Exception("Publicly derived deterministic keys have no private half")
        raw = COINS["Tao"]['main']['secret'].decode('hex') + self.k.to_string() + '\x01' # Always compressed
        return Base58.check_encode(raw)

    def BitcoinWalletImportFormat(self):
        "Returns private key encoded for wallet import"
        if self.public:
            raise Exception("Publicly derived deterministic keys have no private half")
        raw = COINS["bitcoin"]['main']['secret'].decode('hex') + self.k.to_string() + '\x01' # Always compressed
        return Base58.check_encode(raw)

    def ExtendedKey(self, private=True, encoded=True):
        "Return extended private or public key as string, optionally Base58 encoded"
        if self.public is True and private is True:
            raise Exception("Cannot export an extended private key from a public-only deterministic key")
        version = COINS[self.coin][self.network]['private'].decode('hex') if private else COINS[self.coin][self.network]['public'].decode('hex')
        depth = chr(self.depth)
        fpr = self.parent_fpr
        child = struct.pack('>L', self.index)
        chain = self.C
        if self.public is True or private is False:
            data = self.CompressedPublicKey()
        else:
            data = '\x00' + self.PrivateKey()
        raw = version+depth+fpr+child+chain+data
        if not encoded:
            return raw
        else:
            return Base58.check_encode(raw)

    # Debugging methods
    #
    def dump(self):
        "Dump key fields mimicking the BIP0032 test vector format"
        print "   * Identifier"
        print "     * (hex):      ", self.Identifier().encode('hex')
        print "     * (fpr):      ", self.Fingerprint().encode('hex')
        print "     * (main addr):", self.TaoAddress()
        if self.public is False:
            print "   * Secret key"
            print "     * (hex):      ", self.PrivateKey().encode('hex')
            print "     * (taowif):   ", self.TaoWalletImportFormat()
            print "     * (btcwif):   ", self.BitcoinWalletImportFormat()
        print "   * Public key"
        print "     * (hex):      ", self.CompressedPublicKey().encode('hex')
        print "   * Chain code"
        print "     * (hex):      ", self.C.encode('hex')
        print "   * Serialized"
        print "     * (pub hex):  ", self.ExtendedKey(private=False, encoded=False).encode('hex')
        if self.public is False:
            print "     * (prv hex):  ", self.ExtendedKey(private=True, encoded=False).encode('hex')
        print "     * (pub b58):  ", self.ExtendedKey(private=False, encoded=True)
        if self.public is False:
            print "     * (prv b58):  ", self.ExtendedKey(private=True, encoded=True)

def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

def CreateKeyspec():
    import random
    random.seed()
    final = []
    for x in range(0,6):
        leaf = random.SystemRandom().randint(int(0x000000),int(0xFFFFFF))
        final.append(struct.pack("<L",leaf))
    return buffer(''.join(final))

class Keyring(object):
    def __init__(self, password):
        self._cache = {}
        self.Entropy = hasher(password)
        self.m = Key.fromEntropy(self.Entropy)

    def isValid(self):
        return self._valid

    def FromKeyspec(self, keyspec, coin='1Ring', testnet=False, input_type='', input_data=''):
        key = None
        acc = ''
        self.coin = coin
        self.testnet = testnet

        public = False
        key = Key.fromEntropy(self.Entropy, public=public, coin=self.coin, testnet=self.testnet)
        if keyspec == 'm':
            return key
        if testnet:
            net = 'test'
        else:
            net = 'main'
        if input_type == COINS[coin][net]['xkeyprv'] or \
           input_type == COINS[coin][net]['xkeypub']:
            key = Key.fromExtendedKey(input_data, coin=coin)
        _keyspec = list(chunks(keyspec,4))
        for x in range(0,len(_keyspec)):
            spec = '\0' * (4 - len(_keyspec[x])) + _keyspec[x]
            node = struct.unpack("<L",spec)[0]
            key = key.ChildKey(node + _HARDEN)
        return key

if __name__ == '__main__':
    msg = "This is a test message."
    print msg
    key = Keyring("Testing").FromKeyspec("m")
    key.dump()
    enc = key.Encrypt(msg)
    print "Encrypted: " + str(len(enc))
    dec = key.Decrypt(enc)
    print "Decrypted: " 
    print dec
    assert (msg == dec[0])
    sig = key.Sign(msg)
    print "Signature: " + sig
    print "Verify: ",key.Verify(sig,msg,key.TaoAddress())
