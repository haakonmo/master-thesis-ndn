#!/usr/bin/python
import ast
import messageBuf_pb2

from charm.core.engine.util import serializeObject, deserializeObject, objectToBytes, bytesToObject

# all ID-based encryption schemes implemented in Charm
#from charm.schemes.ibenc.ibenc_bb03 import IBE_BB04
#from charm.schemes.ibenc.ibenc_ckrs09 import IBE_CKRS
#from charm.schemes.ibenc.ibenc_lsw08 import IBE_Revoke
#from charm.schemes.ibenc.ibenc_sw05 import IBE_SW05

from charm.toolbox.pairinggroup import PairingGroup,GT
from charm.toolbox.hash_module import Waters,Hash,int2Bytes,integer
from charm.schemes.ibenc.ibenc_waters09 import DSE09
from charm.schemes.ibenc.ibenc_waters05 import IBE_N04
from charm.schemes.pksig.pksig_waters import WatersSig

class IbeWaters09(object):

    def __init__(self):
        self.group = PairingGroup('SS512')
        self.ibe = DSE09(self.group)
        self.algorithm = messageBuf_pb2.Message.WATERS09

    def setup(self):
        return self.ibe.setup()

    def extract(self, master_public_key, master_secret_key, ID):
        secret_key = self.ibe.keygen(master_public_key, master_secret_key, ID)
        return secret_key

    def getRandomKey(self):
        key = self.group.random(GT)
        return key

    def encryptKey(self, master_public_key, ID, key):
        cipher_key = self.ibe.encrypt(master_public_key, key, ID)
        return cipher_key

    def decryptKey(self, master_public_key, secret_key, cipher):
        # master_public_key not used
        key = self.ibe.decrypt(cipher, secret_key)
        return key

class IbsWaters09(object):
    def __init__(self):
        self.group = PairingGroup('SS512')
        self.water = WatersSig(group)

    def setup(self):
        return self.water.setup(5)

    def extract(self, master_public_key, master_secret_key, ID):
        secret_key = self.water.keygen(master_public_key, master_secret_key, ID)
        return secret_key

    def sign(self, master_public_key, secret_key, message):
        signature = self.water.sign(master_public_key, secret_key, message)
        return signature

    def verify(self, master_public_key, ID, message, signature):
        verified = self.water.verify(master_public_key, ID, message, signature)
        return verified

"""Implementation of David Naccahe Identity Based Encryption"""
class IbeWaters05(object):

    def __init__(self):
        self.group = PairingGroup('SS512')
        self.waters_hash = Waters(group)
        self.ibe = IBE_N04(self.group)
        self.algorithm = messageBuf_pb2.Message.WATERS05

    def setup(self):
        return self.ibe.setup()

    def extract(self, master_public_key, master_secret_key, ID):
        # master_public_key not used
        kID = waters_hash.hash(ID)
        secret_key = self.ibe.extract(master_secret_key, kID)
        return secret_key

    def getRandomKey(self):
        key = self.group.random(GT)
        return key

    def encryptKey(self, master_public_key, ID, key):
        kID = waters_hash.hash(ID)
        cipher_key = self.ibe.encrypt(master_public_key, kID, key)
        return cipher_key

    def decryptKey(self, master_public_key, secret_key, cipher):
        key = self.ibe.decrypt(master_public_key, secret_key, cipher)
        return key


