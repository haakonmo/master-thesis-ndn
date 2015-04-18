#!/usr/bin/python
import ast

from charm.core.engine.util import serializeObject, deserializeObject
from charm.toolbox.pairinggroup import PairingGroup

# all ID-based encryption schemes implemented in Charm
# from charm.schemes.ibenc.ibenc_CW13_z import IBE_CW13
from charm.schemes.ibenc.ibenc_bb03 import IBE_BB04
from charm.schemes.ibenc.ibenc_bf01 import IBE_BonehFranklin
from charm.schemes.ibenc.ibenc_ckrs09 import IBE_CKRS
# from charm.schemes.ibenc.ibenc_cllww12_z import IBE_Chen12_z
from charm.schemes.ibenc.ibenc_lsw08 import IBE_Revoke
from charm.schemes.ibenc.ibenc_sw05 import IBE_SW05
from charm.schemes.ibenc.ibenc_waters05 import IBE_N04
# from charm.schemes.ibenc.ibenc_waters05_z import IBE_N04_z
from charm.schemes.ibenc.ibenc_waters09 import DSE09
# from charm.schemes.ibenc.ibenc_waters09_z import DSE09_z

def main():
    group = PairingGroup('MNT224', secparam=1024)
    ibe = IBE_BonehFranklin(group)
    (master_public_key, master_secret_key) = ibe.setup()
    mpk = serializeObject(master_public_key, group)
    print(mpk)
    d = deserializeObject(mpk, group)
    print(d)
    ID = 'user@email.com'
    private_key = ibe.extract(master_secret_key, ID)
    msg = "hello world!!!!!"
    cipher_text = ibe.encrypt(master_public_key, ID, msg)
    print(cipher_text)
    print(ibe.decrypt(master_public_key, private_key, cipher_text))

main()