#!/usr/bin/python
import sys
import logging
import time
import random
import os.path
import util
import ast
from pyndn import Name
from pyndn import Interest
from pyndn import Data
from pyndn import Face
from pyndn.security import KeyType
from pyndn.security import KeyChain
from pyndn.security.identity import IdentityManager
from pyndn.security.identity import MemoryIdentityStorage
from pyndn.security.identity import MemoryPrivateKeyStorage
from pyndn.security.policy import NoVerifyPolicyManager
from pyndn.util import Blob

from charm.core.engine.util import serializeObject, deserializeObject
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor
from identityBasedCrypto import IbeWaters09, IbsWaters

from charm.schemes.pkenc.pkenc_rsa import RSA_Enc, RSA_Sig
from charm.schemes.pksig.pksig_ecdsa import ECDSA
from charm.toolbox.ecgroup import ECGroup,ZR,G
from charm.toolbox.PKSig import PKSig
from charm.toolbox.eccurve import prime192v2
from charm.toolbox.IBEnc import *
from charm.toolbox.pairinggroup import PairingGroup,GT, ZR,G1,pair, G2, GT

def getKey():
    face = Face("129.241.208.115", 6363)

    # Use the system default key chain and certificate name to sign commands.
    keyChain = KeyChain()
    face.setCommandSigningInfo(keyChain, keyChain.getDefaultCertificateName())
    # util.dump(keyChain.getDefaultCertificateName())
    # Also use the default certificate name to sign data packets.    
    face.expressInterest("/ndn/no/ntnu/KEY", onData, onTimeout)

    while True:
        face.processEvents()
        # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        time.sleep(0.01)

    face.shutdown()

def onData(interest, data):
    util.dump("Data received: ", interest.getName().toUri())
    util.dumpData(data)

def onTimeout(interest):
    util.dump("Time out for interest", interest.getName().toUri())

class Ibe(object):

    def __init__(self):
        global number
        logging.info("Identity-Based Encryption: ")
        self.ibe_scheme = IbeWaters09()
        
        results = 0.0
        for i in range (0, number):
            start = time.clock()
            (self.master_public_key, self.master_secret_key) = self.ibe_scheme.setup()
            end = time.clock()
            results += end-start
        mean = results / number
        
        publicKeySize = len(Blob(objectToBytes(self.master_public_key, self.ibe_scheme.group)))
        secretKeySize = len(Blob(objectToBytes(self.master_secret_key, self.ibe_scheme.group)))

        logging.info("MPK: " + str(publicKeySize) + " bytes.")
        logging.info("MSK: " + str(secretKeySize) + " bytes.")
        logging.info("KeyPair creating time: " +  str(mean))
        logging.info("")

class Ibs(object):

    def __init__(self):
        global number
        logging.info("Identity-Based Signature: ")
        self.ibs_scheme = IbsWaters()

        results = 0.0
        for i in range (0, number):
            start = time.clock()
            (self.master_public_key, self.master_secret_key) = self.ibs_scheme.setup()
            end = time.clock()
            results += end-start
        mean = results / number

        sPublicKeySize = len(Blob(objectToBytes(self.master_public_key, self.ibs_scheme.group)))
        sSecretKeySize = len(Blob(objectToBytes(self.master_secret_key, self.ibs_scheme.group)))
        
        logging.info("MPK: " + str(sPublicKeySize) + " bytes.")
        logging.info("MSK: " + str(sSecretKeySize) + " bytes.")
        logging.info("KeyPair creating time: " +  str(mean))
        logging.info("")

def measure(function):
    results = 0.0
    for i in range (0, number):
        start = time.clock()
        function()
        end = time.clock()
        results += end-start
    mean = results / number
    logging.info("Mean time: " + str(mean))

def test():
    global number
    global cek
    global data
    ibe = Ibe()
    ibs = Ibs()

    ID = "/ndn/no/ntnu/haakon"
    data = "this is a short message that should be signed and encrypted."
    cek = ibe.ibe_scheme.getRandomKey()
    cekSize = len(Blob(extractor(cek)))
    logging.info("CEK: ")
    logging.info(extractor(cek))
    logging.info(Blob(extractor(cek)))

    results = 0.0
    for i in range (0, number):
        start = time.clock()
        ibe.ibe_scheme.extract(ibe.master_public_key, ibe.master_secret_key, ID)
        end = time.clock()
        results += end-start
    mean = results / number
    logging.info("PrivateKey creating time: " + str(mean))

    private_key = ibe.ibe_scheme.extract(ibe.master_public_key, ibe.master_secret_key, ID)
    private_key_encoded = objectToBytes(private_key, ibe.ibe_scheme.group)
    privateKeySize = len(Blob(private_key_encoded))
    logging.info("PrivateKey: " + str(privateKeySize) + " bytes.")
    
    logging.info("Encryption time PK:")
    cipher = encrypt(cek, private_key_encoded)
    logging.info("Cipher PK: " + str(len(cipher)) + " bytes.")
    logging.info("")

    results = 0.0
    for i in range (0, number):
        start = time.clock()
        ibs.ibs_scheme.extract(ibs.master_public_key, ibs.master_secret_key, ID)
        end = time.clock()
        results += end-start
    mean = results / number
    logging.info("SigningPrivateKey creating time: " + str(mean))

    signature_private_key = ibs.ibs_scheme.extract(ibs.master_public_key, ibs.master_secret_key, ID)
    signature_private_key_encoded = objectToBytes(signature_private_key, ibs.ibs_scheme.group)
    signaturePrivateKeySize = len(Blob(signature_private_key_encoded))
    logging.info("SigningPrivateKey: " + str(signaturePrivateKeySize) + " bytes.")
    logging.info("Encryption time SPK:")
    cipher = encrypt(cek, signature_private_key_encoded)
    logging.info("Cipher SPK: " + str(len(cipher)) + " bytes.")
    logging.info("")

    signature = ibs.ibs_scheme.water.sign(ibs.master_public_key, signature_private_key, data)
    signatureSize = len(Blob(objectToBytes(signature, ibs.ibs_scheme.group)))
    logging.info("Signature: " + str(signatureSize) + " bytes.")
    results = 0.0
    for i in range (0, number):
        start = time.clock()
        ibs.ibs_scheme.water.sign(ibs.master_public_key, signature_private_key, data)
        end = time.clock()
        results += end-start
    mean = results / number
    logging.info("Signing time: " + str(mean))

    results = 0.0
    for i in range (0, number):
        start = time.clock()
        verified = ibs.ibs_scheme.water.verify(ibs.master_public_key, ID, data, signature)
        if not verified: break
        end = time.clock()
        results += end-start
    mean = results / number
    logging.info("Verification time: " + str(mean))
    logging.info("")

    results = 0.0
    for i in range (0, number):
        start = time.clock()
        ibe.ibe_scheme.encryptKey(ibe.master_public_key, ID, cek)
        end = time.clock()
        results += end-start
    mean = results / number
    logging.info("Encrypt CEK time: " + str(mean))

    encryptedCek = ibe.ibe_scheme.encryptKey(ibe.master_public_key, ID, cek)
    encryptedCekSize = len(Blob(objectToBytes(encryptedCek, ibe.ibe_scheme.group)))

    logging.info("CEK: " + str(cekSize) + " bytes.")
    logging.info("Encrypted CEK: " + str(encryptedCekSize) + " bytes.")

    results = 0.0
    for i in range (0, number):
        start = time.clock()
        ibe.ibe_scheme.decryptKey(ibe.master_public_key, private_key, encryptedCek)
        end = time.clock()
        results += end-start
    mean = results / number
    logging.info("Decrypt CEK time: " + str(mean))
    logging.info("")

def encrypt(key, content):
    a = SymmetricCryptoAbstraction(extractor(key))
    
    results = 0.0
    for i in range (0, number):
        start = time.clock()
        a.encrypt(content)
        end = time.clock()
        results += end-start
    mean = results / number
    logging.info("AES encrypt: " + str(mean))

    cipher = a.encrypt(content)
    return cipher

def decrypt(key, cipher):
    a = SymmetricCryptoAbstraction(extractor(key))

    results = 0.0
    for i in range (0, number):
        start = time.clock()
        a.decrypt(content)
        end = time.clock()
        results += end-start
    mean = results / number
    logging.info("AES decrypt: " + str(mean))

    content = a.decrypt(cipher)
    return content

def rsa():
    global number
    global cek
    global data
    rsa = RSA_Enc()

    results = 0.0
    for i in range (0, number):
        start = time.clock()
        (public_key, secret_key) = rsa.keygen(1024)
        end = time.clock()
        results += end-start
    mean = results / number
    logging.info("RSA key generation time: " + str(mean))

    msg = str(extractor(cek))

    results = 0.0
    for i in range (0, number):
        start = time.clock()
        rsa.encrypt(public_key, msg)
        end = time.clock()
        results += end-start
    mean = results / number
    logging.info("RSA encryption time: " + str(mean))

    cipher_text = rsa.encrypt(public_key, msg)

    results = 0.0
    for i in range (0, number):
        start = time.clock()
        rsa.decrypt(public_key, secret_key, cipher_text)
        end = time.clock()
        results += end-start
    mean = results / number
    logging.info("RSA decryption time: " + str(mean))

    decrypted_msg = rsa.decrypt(public_key, secret_key, cipher_text)
    decrypted_msg == msg

    msg = str(data)
    rsa = RSA_Sig()
    (public_key, secret_key) = rsa.keygen(1024)

    results = 0.0
    for i in range (0, number):
        start = time.clock()
        rsa.sign(secret_key, msg)
        end = time.clock()
        results += end-start
    mean = results / number
    logging.info("RSA signing time: " + str(mean))
    signature = rsa.sign(secret_key, msg)

    results = 0.0
    for i in range (0, number):
        start = time.clock()
        rsa.verify(public_key, msg, signature)
        end = time.clock()
        results += end-start
    mean = results / number
    logging.info("RSA verify time: " + str(mean))
    logging.info("")
    rsa.verify(public_key, msg, signature)

def ecdsa():
    group = ECGroup(prime192v2)
    ecdsa = ECDSA(group)

    results = 0.0
    for i in range (0, number):
        start = time.clock()
        (public_key, secret_key) = ecdsa.keygen(0)
        end = time.clock()
        results += end-start
    mean = results / number
    logging.info("ECDSA key generation time: " + str(mean))
    (public_key, secret_key) = ecdsa.keygen(0)

    msg = "hello world! this is a test message."

    results = 0.0
    for i in range (0, number):
        start = time.clock()
        ecdsa.sign(public_key, secret_key, msg)
        end = time.clock()
        results += end-start
    mean = results / number
    logging.info("ECDSA signing time: " + str(mean))
    signature = ecdsa.sign(public_key, secret_key, msg)

    results = 0.0
    for i in range (0, number):
        start = time.clock()
        ecdsa.verify(public_key, signature, msg)
        end = time.clock()
        results += end-start
    mean = results / number
    logging.info("ECDSA verify time: " + str(mean))    
    ecdsa.verify(public_key, signature, msg)

def ibcKeySize():
    group = PairingGroup('SS512')
    g1 = group.random(G1)
    g2 = group.random(G2)
    gt = group.random(GT)
    logging.info("G1:" + str(g1) + ", length: " + str(len(Blob(objectToBytes(g1, group)))) + " bytes.")
    logging.info("G2:" + str(g2) + ", length: " + str(len(Blob(objectToBytes(g2, group)))) + " bytes.")
    logging.info("GT:" + str(gt) + ", length: " + str(len(Blob(objectToBytes(gt, group)))) + " bytes.")

def main():
    logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

    global number
    number = 100
    test()
    rsa()
    ecdsa()
    ibcKeySize()

main()