#!/usr/bin/python
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
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor
from identityBasedCrypto import IbeWaters09

class Device(object):

    def __init__(self, face, keyChain, certificateName, baseName, deviceName):
        self.ibe_scheme = IbeWaters09()

        self.face = face
        self.keyChain = keyChain
        self.certificateName = certificateName

        self.baseName = Name(baseName)
        self.deviceName = Name(self.baseName).append(deviceName)

    # Methods for a device that requests Data
    def requestData(self):
        """
        Request data

        The suffix components count includes the implicit digest component of the full name in the data packet. 
        For example, if the interest name is the prefix /a/b and the data packet name is /a/b/c, 
        then the data packet name has 2 suffix components: 'c' and the implicit digest which is not shown.
        """
        # Session used in namePrefix
        session = str(int(round(util.getNowMilliseconds() / 1000.0)))
        self.name = Name(self.baseName).append("device2").append("sensor_pull").append(session)

        interest = Interest(self.name)
        # Set the minSuffxComponents to prevent any other application to answer, i.e. /ndn/no/ntnu
        #interest.setMinSuffixComponents(3)
        keyLocator = KeyLocator()
        keyLocator.setType(KeyLocatorType.KEYNAME)
        keyLocator.setKeyName(self.deviceName)
        interest.setKeyLocator(keyLocator)

        util.dump(self.certificateName)
        self.keyChain.sign(interest, self.certificateName)
        interest.wireEncode()

        util.dump("Expressing interest name: ", interest.toUri())
        self.face.expressInterest(interest, self.onData, self.onTimeout)

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
                messageMPK = deserializeObject(masterPublicKeyDict, self.ibe_scheme.group)
                if not (self.master_public_key == messageMPK):
                    logging.error("MasterPulicKey doesnt match!!")

                #Decrypt identityBasedEncrypedKey
                identityBasedEncryptedKeyDict = ast.literal_eval(message.identityBasedEncryptedKey)
                identityBasedEncryptedKey = deserializeObject(identityBasedEncryptedKeyDict, self.ibe_scheme.group)
                key = self.ibe_scheme.decryptKey(self.master_public_key, self.private_key, identityBasedEncryptedKey)

                #Decrypt encryptedMessage
                a = SymmetricCryptoAbstraction(extractor(key))
                data = a.decrypt(message.encryptedMessage)

                # Use data from device to something ..
                util.dump(str(data))

    # Methods for a device that offers Data
    def registerPrefix(self):
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
        

        data = Data(interest.getName())
        contentData = "This should be sensordata blablabla"

        # Symmetric key for encryption
        self.key = self.ibe_scheme.getRandomKey()
        # Identity-Based Encryption of symmetric key
        identityBasedEncryptedKey = self.ibe_scheme.encryptKey(self.master_public_key, ID, self.key)
        identityBasedEncryptedKey = str(serializeObject(identityBasedEncryptedKey, self.ibe_scheme.group))
        # Master Public Key
        identityBasedMasterPublicKey = str(serializeObject(self.master_public_key, self.ibe_scheme.group))

        # Symmetric AES encryption of contentData
        a = SymmetricCryptoAbstraction(extractor(self.key))
        encryptedMessage = a.encrypt(contentData)

        message = messageBuf_pb2.Message()
        message.identityBasedMasterPublicKey = identityBasedMasterPublicKey
        message.identityBasedEncryptedKey = identityBasedEncryptedKey
        message.encryptedMessage = encryptedMessage
        message.encryptionType = messageBuf_pb2.Message.AES
        message.timestamp = int(round(util.getNowMilliseconds() / 1000.0)) 
        message.type = messageBuf_pb2.Message.SENSOR_DATA
        
        content = message.SerializeToString()
        data.setContent(Blob(content))
        self.keyChain.sign(data, self.certificateName)
        encodedData = data.wireEncode()

        logging.info("Encrypting with ID: " + ID)
        transport.send(encodedData.toBuffer())
        logging.info("Sent encrypted data..")

    def onRegisterFailed(self, prefix):
        util.dump("Register failed for prefix", prefix.toUri())

    # General methods for all devices

    def onTimeout(self, interest):
        util.dump("Time out for interest", interest.getName().toUri())

    def onVerifiedData(self, data):
        #TODO
        print("Data packet verified")

    def onVerifyDataFailed(self, data):
        #TODO
        print("Data packet failed verification")

    def onVerifiedInterest(self, data):
        #TODO
        print("Data packet verified")

    def onVerifyInterestFailed(self, data):
        #TODO
        print("Data packet failed verification")

    def requestIdentityBasedPrivateKey(self):
        """
        Create PK/SK for initialization
        Message.INIT 
        send name and PK
        """

        # Create a keyPair for initialization process
        (master_public_key, master_secret_key) = self.ibe_scheme.setup()
        self.temp_master_public_key = master_public_key
        ID = self.deviceName.toUri()
        self.temp_private_key = self.ibe_scheme.extract(master_public_key, master_secret_key, ID)

        # Make each init unique with a session
        session = str(int(round(util.getNowMilliseconds() / 1000.0)))

        #TODO append tempMpk to name , as base64 encoded
        encodedTempMasterPublicKey = objectToBytes(self.temp_master_public_key, self.ibe_scheme.group)
        name = Name(self.baseName).append("pkg").append("initDevice").append(session).append(encodedTempMasterPublicKey)
        interest = Interest(name)
        keyLocator = KeyLocator()
        keyLocator.setType(KeyLocatorType.KEYNAME)
        keyLocator.setKeyName(self.deviceName)
        interest.setKeyLocator(keyLocator)

        logging.info("Expressing interest name: " + name.toUri())
        self.face.expressInterest(interest, self.onInitData, self.onTimeout)

    def onInitData(self, interest, data):
        """
        1. Decrypt message
        2. Decode message
        """
        self.keyChain.verifyData(data, self.onVerifiedData, self.onVerifyDataFailed)
        
        message = messageBuf_pb2.Message()
        message.ParseFromString(data.getContent().toRawStr())

        if (message.type == messageBuf_pb2.Message.INIT):
            if (message.encryptionType == messageBuf_pb2.Message.AES):
                #Decrypt identityBasedEncrypedKey
                identityBasedEncryptedKeyDict = ast.literal_eval(message.identityBasedEncryptedKey)
                identityBasedEncryptedKey = deserializeObject(identityBasedEncryptedKeyDict, self.ibe_scheme.group)
                key = self.ibe_scheme.decryptKey(self.temp_master_public_key, self.temp_private_key, identityBasedEncryptedKey)
                
                #Decrypt encryptedMessage
                a = SymmetricCryptoAbstraction(extractor(key))
                privateKeyEncoded = a.decrypt(message.encryptedMessage)

                logging.info(privateKeyEncoded)

                masterPublicKeyDict     = ast.literal_eval(message.identityBasedMasterPublicKey)
                self.private_key        = bytesToObject(privateKeyEncoded, self.ibe_scheme.group)
                self.master_public_key  = deserializeObject(masterPublicKeyDict, self.ibe_scheme.group)
                logging.info("Initialization success! PrivateKey and MasterPublicKey received.")