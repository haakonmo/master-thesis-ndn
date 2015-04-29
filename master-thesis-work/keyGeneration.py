#!/usr/bin/python
import ast

from charm.core.engine.util import serializeObject, deserializeObject, objectToBytes, bytesToObject

# all ID-based encryption schemes implemented in Charm
# from charm.schemes.ibenc.ibenc_CW13_z import IBE_CW13
from charm.schemes.ibenc.ibenc_bb03 import IBE_BB04
from charm.schemes.ibenc.ibenc_ckrs09 import IBE_CKRS
# from charm.schemes.ibenc.ibenc_cllww12_z import IBE_Chen12_z
from charm.schemes.ibenc.ibenc_lsw08 import IBE_Revoke
from charm.schemes.ibenc.ibenc_sw05 import IBE_SW05

# from charm.schemes.ibenc.ibenc_waters05_z import IBE_N04_z
# from charm.schemes.ibenc.ibenc_waters09_z import DSE09_z

from charm.schemes.ibenc.ibenc_waters05 import IBE_N04
from charm.toolbox.pairinggroup import PairingGroup,GT
from charm.toolbox.hash_module import Waters,Hash,int2Bytes,integer

class IbeWaters09(object):

    def __init__(self):
        self.group = PairingGroup('SS512')
        self.ibe = DSE09(self.group)

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

    def decryptKey(self, secret_key, cipher):
        key = self.ibe.decrypt(cipher, secret_key)
        return key

def ibe_waters05():
    group = PairingGroup('SS512')
    waters_hash = Waters(group)
    ibe = IBE_N04(group)
    (master_public_key, master_key) = ibe.setup()
    ID = "bob@mail.com"
    kID = waters_hash.hash(ID)
    secret_key = ibe.extract(master_key, kID)
    msg = group.random(GT)

    cipher_text = ibe.encrypt(master_public_key, kID, msg)
    decrypted_msg = ibe.decrypt(master_public_key, secret_key, cipher_text)
    print(decrypted_msg == msg)

from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.ibenc.ibenc_waters09 import DSE09
def ibe_waters09():
    group = PairingGroup('SS512')
    ibe = DSE09(group)
    ID = "user2@email.com"
    (master_public_key, master_secret_key) = ibe.setup()
    secret_key = ibe.keygen(master_public_key, master_secret_key, ID)
    msg = group.random(GT)    
    cipher_text = ibe.encrypt(master_public_key, msg, ID)
    decrypted_msg = ibe.decrypt(cipher_text, secret_key)
    print(decrypted_msg == msg)

from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.ibenc.ibenc_bf01 import IBE_BonehFranklin
def ibe_bf01():
    group = PairingGroup('MNT224', secparam=1024)
    ibe = IBE_BonehFranklin(group)
    (master_public_key, master_secret_key) = ibe.setup()
    mpk = serializeObject(master_public_key, group)
    print(mpk)
    d = deserializeObject(mpk, group)
    print(d)
    ID = '/ndn/ntnu/jaja'
    private_key = ibe.extract(master_secret_key, ID)
    msg = group.random(GT)
    cipher_text = ibe.encrypt(master_public_key, ID, msg)
    print(cipher_text)
    print(ibe.decrypt(master_public_key, private_key, cipher_text))