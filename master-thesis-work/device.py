#!/usr/bin/python3
import messageBuf_pb2
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
from pyndn.key_locator import KeyLocator, KeyLocatorType
from pyndn.security import KeyType
from pyndn.security import KeyChain
from pyndn.security.identity import IdentityManager
from pyndn.security.identity import MemoryIdentityStorage
from pyndn.security.identity import MemoryPrivateKeyStorage
from pyndn.security.policy import NoVerifyPolicyManager
from pyndn.util import Blob

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from watchdog.events import FileModifiedEvent

from charm.core.engine.util import serializeObject, deserializeObject
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

from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor
from keyGeneration import IbeWaters09

class SensorPull(object):

    def __init__(self, face, keyChain, certificateName, baseName):
        self.ibeScheme = IbeWaters09()

        self.face = face
        self.keyChain = keyChain
        self.certificateName = certificateName

        self.baseName = Name(baseName)
        self.deviceName = Name(self.baseName).append("device1")
        
        #self.name = Name(baseName).append("sensor_pull")
        #util.dump("Expressing interest name: ", self.name.toUri())
        #self.face.expressInterest(self.name, self.onData, self.onTimeout)

    def onInterest(self, prefix, interest, transport, registeredPrefixId):
        util.dumpInterest(interest)

    def onData(self, interest, data):
        """
        1. Decrypt message
        2. Decode message
        """
        self.keyChain.verifyData(data, self.onVerifiedData, self.onVerifyDataFailed)
        
        message = messageBuf_pb2.Message()
        message.ParseFromString(data.getContent().toRawStr())

        if (message.type == messageBuf_pb2.Message.SENSOR_DATA):
            if (message.encryptionType == messageBuf_pb2.Message.AES):
                #Compare master_public_key
                masterPublicKeyDict = ast.literal_eval(message.identityBasedMasterPublicKey)
                messageMPK = deserializeObject(masterPublicKeyDict, self.ibeScheme.group)
                if not (self.master_public_key == messageMPK):
                    logging.error("MPK doesnt match!!")

                #Decrypt identityBasedEncrypedKey
                identityBasedEncryptedKeyDict = ast.literal_eval(message.identityBasedEncryptedKey)
                identityBasedEncryptedKey = deserializeObject(identityBasedEncryptedKeyDict, self.ibeScheme.group)
                key = self.ibeScheme.decryptKey(self.private_key, identityBasedEncryptedKey)
                util.dump(identityBasedEncryptedKey)
                
                #Decrypt encryptedMessage
                a = SymmetricCryptoAbstraction(extractor(key))
                data = a.decrypt(message.encryptedMessage)
                util.dump(str(data))

        if (message.type == messageBuf_pb2.Message.INIT):
            #TODO private key MUST be encrypted somehow..
            if (message.encryptionType == messageBuf_pb2.Message.NONE):
                privateKeyDict = ast.literal_eval(message.encryptedMessage)
                masterPublicKeyDict = ast.literal_eval(message.identityBasedMasterPublicKey)
                self.private_key = deserializeObject(privateKeyDict, self.ibeScheme.group)
                self.master_public_key = deserializeObject(masterPublicKeyDict, self.ibeScheme.group)

    def onTimeout(self, interest):
        util.dump("Time out for interest", interest.getName().toUri())

    def onRegisterFailed(self, prefix):
        util.dump("Register failed for prefix", prefix.toUri())

    def onVerifiedData(self, data):
        #TODO
        print("Data packet verified")

    def onVerifyDataFailed(self, data):
        #TODO
        print("Data packet failed verification")

    def requestIdentityBasedPrivateKey(self):
        """
        Create PK/SK for initialization
        Message.INIT 
        send name and PK
        """
        name = Name(self.baseName).append("pkg").append("initDevice")
        interest = Interest(name)
        keyLocator = KeyLocator()
        keyLocator.setType(KeyLocatorType.KEYNAME)
        keyLocator.setKeyName(self.deviceName)
        interest.setKeyLocator(keyLocator)

        util.dump("Expressing interest name: ", name.toUri())
        self.face.expressInterest(interest, self.onData, self.onTimeout)

    def requestData(self):
        """
        Request data

        The suffix components count includes the implicit digest component of the full name in the data packet. 
        For example, if the interest name is the prefix /a/b and the data packet name is /a/b/c, 
        then the data packet name has 2 suffix components: 'c' and the implicit digest which is not shown.
        """
        #Session used in namePrefix
        session = int(round(util.getNowMilliseconds() / 1000.0))
        self.name = Name(self.baseName).append("device2").append("sensor_pull").append(str(session))

        interest = Interest(self.name)
        #interest.setMinSuffixComponents(3)
        #interest.setMaxSuffixComponents(6)
        keyLocator = KeyLocator()
        keyLocator.setType(KeyLocatorType.KEYNAME)
        keyLocator.setKeyName(self.deviceName)
        interest.setKeyLocator(keyLocator)

        util.dump(self.certificateName)
        self.keyChain.sign(interest, self.certificateName)
        interest.wireEncode()

        util.dump("Expressing interest name: ", interest.toUri())
        self.face.expressInterest(interest, self.onData, self.onTimeout)

class SensorData(object):

    def __init__(self, face, keyChain, certificateName, baseName):
        self.ibeScheme = IbeWaters09()

        self.face = face
        self.keyChain = keyChain
        self.certificateName = certificateName

        self.baseName = Name(baseName)
        self.deviceName = Name(self.baseName).append("device2")

        self.prefix = Name(self.deviceName).append("sensor_pull")
        util.dump("Register prefix", self.prefix.toUri())
        self.face.registerPrefix(self.prefix, self.onInterest, self.onRegisterFailed)

    def onInterest(self, prefix, interest, transport, registeredPrefixId):
        """
        1. Encode message
        2. Encrypt message = cipher
        """
        #util.dumpInterest(interest)
        self.keyChain.verifyInterest(interest, self.onVerifiedInterest, self.onVerifyInterestFailed)

        ID = ""
        if interest.getKeyLocator().getType() == KeyLocatorType.KEYNAME:
            ID = interest.getKeyLocator().getKeyName().toUri()
        logging.info("Encrypting with ID: " + ID)

        data = Data(interest.getName())
        message = "This should be sensordata blablabla"
        self.encryptionKey = self.ibeScheme.getRandomKey()
        identityBasedEncryptedKey = self.ibeScheme.encryptKey(self.master_public_key, ID, self.encryptionKey)
        identityBasedEncryptedKey = str(serializeObject(identityBasedEncryptedKey, self.ibeScheme.group))

        a = SymmetricCryptoAbstraction(extractor(self.encryptionKey))
        encryptedMessage = a.encrypt(message)

        logging.info(encryptedMessage)

        message = messageBuf_pb2.Message()
        message.identityBasedMasterPublicKey = str(serializeObject(self.master_public_key, self.ibeScheme.group))
        message.identityBasedEncryptedKey = identityBasedEncryptedKey
        message.encryptedMessage = encryptedMessage
        message.encryptionType = messageBuf_pb2.Message.AES
        message.timestamp = int(round(util.getNowMilliseconds() / 1000.0)) 
        message.type = messageBuf_pb2.Message.SENSOR_DATA
        
        content = message.SerializeToString()
        data.setContent(Blob(content))
        self.keyChain.sign(data, self.certificateName)
        encodedData = data.wireEncode()

        logging.info("Sent data..")
        transport.send(encodedData.toBuffer())

    def onData(self, interest, data):
        """
        if Message.INIT_RESPONSE then decrypt and store privateKey, store master_public_key
        """
        message = messageBuf_pb2.Message()
        message.ParseFromString(data.getContent().toRawStr())
        if (message.type == messageBuf_pb2.Message.INIT):
            #TODO private key MUST be encrypted somehow..
            if (message.encryptionType == messageBuf_pb2.Message.NONE):
                privateKeyDict = ast.literal_eval(message.encryptedMessage)
                masterPublicKeyDict = ast.literal_eval(message.identityBasedMasterPublicKey)
                self.private_key = deserializeObject(privateKeyDict, self.ibeScheme.group)
                self.master_public_key = deserializeObject(masterPublicKeyDict, self.ibeScheme.group)

    def onTimeout(self, interest):
        util.dump("Time out for interest", interest.getName().toUri())

    def onRegisterFailed(self, prefix):
        util.dump("Register failed for prefix", prefix.toUri())

    def onVerifiedInterest(self, interest):
        #TODO
        print("Interest packet verified")

    def onVerifyInterestFailed(self, interest):
        #TODO
        print("Interest packet failed verification")

    def onVerifiedData(self, data):
        #TODO
        print("Data packet verified")

    def onVerifyDataFailed(self, data):
        #TODO
        print("Data packet failed verification")

    def requestIdentityBasedPrivateKey(self):
        """
        Create PK/SK for initialization
        Message.INIT 
        send name and PK
        """
        name = self.baseName.append("pkg").append("initDevice")
        interest = Interest(name)
        keyLocator = KeyLocator()
        keyLocator.setType(KeyLocatorType.KEYNAME)
        keyLocator.setKeyName(self.deviceName)
        interest.setKeyLocator(keyLocator)

        util.dump("Expressing interest name: ", name.toUri())
        self.face.expressInterest(interest, self.onData, self.onTimeout)