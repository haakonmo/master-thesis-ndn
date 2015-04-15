#!/usr/bin/python3
from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.ibenc.ibenc_bf01 import IBE_BonehFranklin
def main():
    group = PairingGroup('MNT224', secparam=1024)
    ibe = IBE_BonehFranklin(group)
    (master_public_key, master_secret_key) = ibe.setup()
    ID = 'user@email.com'
    private_key = ibe.extract(master_secret_key, ID)
    msg = "hello world!!!!!"
    cipher_text = ibe.encrypt(master_public_key, ID, msg)
    print(cipher_text)
    print(ibe.decrypt(master_public_key, private_key, cipher_text))

main()