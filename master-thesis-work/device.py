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
from pyndn import MetaInfo
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
from identityBasedCrypto import IbeWaters09, IbsWaters

class Device(object):

    def __init__(self, face, keyChain, certificateName, baseName, deviceName):
        self.ibe_scheme = IbeWaters09()
        self.ibs_scheme = IbsWaters()

        self.face = face
        self.keyChain = keyChain
        self.certificateName = certificateName

        self.baseName = Name(baseName)
        self.deviceName = Name(self.baseName).append(deviceName)

    # Methods for a device that requests Data
    def requestData(self):
        """
        Interest:
            Name: /ndn/no/ntnu/<device>/sensorPull/<nonce>
            Selector: KeyLocator = ID

        The ID of the requesting Device is stored in KeyLocator in the Interest, 

        Sign the Interest and send.
        """
        # Session used in namePrefix
        session = str(int(round(util.getNowMilliseconds() / 1000.0)))
        self.name = Name(self.baseName).append("device2").append("sensorPull").append(session)

        interest = Interest(self.name)
        self.ibs_scheme.signInterest(self.signature_master_public_key, self.signature_private_key, self.deviceName, interest)
        # Set the minSuffxComponents to prevent any other application to answer, i.e. /ndn/no/ntnu
        #interest.setMinSuffixComponents(3)
        # keyLocator = KeyLocator()
        # keyLocator.setType(KeyLocatorType.KEYNAME)
        # keyLocator.setKeyName(self.deviceName)
        # interest.setKeyLocator(keyLocator)

        # self.keyChain.sign(interest, self.certificateName)
        interest.wireEncode()

        logging.info("Expressing interest name: " + interest.toUri())
        self.face.expressInterest(interest, self.onData, self.onTimeout)

    def onData(self, interest, data):
        """
        Data:
            Content: 
                master_public_key to PKG
                ibeKey = ibe(randomKey)
                cipher = encrypt(PrivateKey, randomKey)

        Decode the master_public_key and compare it to the device.master_public_key (if they match, they trust the same PKG)
        Decrypt the symmetric key, and decrypt the cipher

        Sensor Data reveiced! 
        """
        #self.keyChain.verifyData(data, self.onVerifiedData, self.onVerifyDataFailed)
        self.ibs_scheme.verifyData(self.signature_master_public_key, data, self.onVerifiedData, self.onVerifyDataFailed)

        message = messageBuf_pb2.Message()
        message.ParseFromString(data.getContent().toRawStr())

        # TODO: compare nonce
        session = message.nonce

        if (message.type == messageBuf_pb2.Message.SENSOR_DATA):
            if (message.encAlgorithm == messageBuf_pb2.Message.AES):

                # Check if IBS algorithm is the same
                if not (self.ibs_scheme.algorithm == message.ibsAlgorithm)
                    logging.error("IBS algorithm doesnt match! Receiver: "+self.ibs_scheme.algorithm+", Sender: "+message.ibsAlgorithm)

                #Compare signature_master_public_key
                signatureMasterPublicKeyDict = ast.literal_eval(message.identityBasedSignatureMasterPublicKey)
                messageSignatureMPK = deserializeObject(signatureMasterPublicKeyDict, self.ibs_scheme.group)
                if not (self.signature_master_public_key == messageSignatureMPK):
                    logging.error("SignatureMasterPulicKey does not match!")

                # Check if IBE algorithm is the same
                if not (self.ibe_scheme.algorithm == message.ibeAlgorithm)
                    logging.error("IBE algorithm doesnt match! Receiver: "+self.ibe_scheme.algorithm+", Sender: "+message.ibeAlgorithm)
                
                #Compare master_public_key
                masterPublicKeyDict = ast.literal_eval(message.identityBasedMasterPublicKey)
                messageMPK = deserializeObject(masterPublicKeyDict, self.ibe_scheme.group)
                if not (self.master_public_key == messageMPK):
                    logging.error("MasterPulicKey does not match!")

                #Decrypt identityBasedEncrypedKey
                identityBasedEncryptedKeyDict = ast.literal_eval(message.identityBasedEncryptedKey)
                identityBasedEncryptedKey = deserializeObject(identityBasedEncryptedKeyDict, self.ibe_scheme.group)
                key = self.ibe_scheme.decryptKey(self.master_public_key, self.private_key, identityBasedEncryptedKey)

                #Decrypt encryptedMessage
                a = SymmetricCryptoAbstraction(extractor(key))
                data = a.decrypt(message.encryptedMessage)

                # Use data from device to something ..
                logging.info("Data received: " + str(data))

    # Methods for a device that offers Data
    def registerPrefix(self):
        """
        Announce that this device can be reached at a prefix
        """
        self.prefix = Name(self.deviceName).append("sensorPull")
        logging.info("Register prefix" + self.prefix.toUri())
        self.face.registerPrefix(self.prefix, self.onInterest, self.onRegisterFailed)

    def onInterest(self, prefix, interest, transport, registeredPrefixId):
        """
        Interest:
            Name: /ndn/no/ntnu/<device>/sensorPull/<nonce>
            Selector: KeyLocator = ID

        The ID of the requesting Device is stored in KeyLocator in the Interest, 
        and the TemporaryMasterPublicKey to the device is sent in the Interest Name as shown above.

        Encrypt a symmetric key with the MasterPublicKey and the ID.
        Encrypt the SensorData with symmetric encryption, using the symmetric key.
        
        Data:
            Content: 
                master_public_key to PKG
                ibeKey = ibe(randomKey)
                cipher = encrypt(sensorData, randomKey)

        Sign the Data and send.
        """
        #util.dumpInterest(interest)
        #self.keyChain.verifyInterest(interest, self.onVerifiedInterest, self.onVerifyInterestFailed)
        self.ibs_scheme.verifyInterest(self.signature_master_public_key, interest, self.onVerifiedInterest, self.onVerifyInterestFailed)

        ID = ""
        if interest.getKeyLocator().getType() == KeyLocatorType.KEYNAME:
            ID = interest.getKeyLocator().getKeyName().toUri()
        
        keyName = interest.getName()
        session = keyName.get(keyName.size()-1).toEscapedString()

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
        message.encAlgorithm = messageBuf_pb2.Message.AES
        message.ibeAlgorithm = self.ibe_scheme.algorithm
        message.nonce = session
        message.timestamp = int(round(util.getNowMilliseconds() / 1000.0)) 
        message.type = messageBuf_pb2.Message.SENSOR_DATA
        
        content = message.SerializeToString()
        metaInfo = MetaInfo()
        metaInfo.setFreshnessPeriod(30000) # 30 seconds
        data.setContent(Blob(content))
        data.setMetaInfo(metaInfo)

        self.ibs_scheme.signData(self.signature_master_public_key, self.signature_private_key, self.deviceName, data)
        #self.keyChain.sign(data, self.certificateName)
        # signature =  # subclass of signature.py
        # data.setSignature(signature)
        #
        #
        encodedData = data.wireEncode()

        logging.info("Encrypting with ID: " + ID)
        transport.send(encodedData.toBuffer())
        logging.info("Sent encrypted Data")

    def onRegisterFailed(self, prefix):
        logging.info("Register failed for prefix" + prefix.toUri())


    # General methods for all devices
    def onTimeout(self, interest):
        logging.info("Time out for interest" + interest.getName().toUri())

    def onVerifiedData(self, data):
        #TODO
        logging.info("Data packet verified")

    def onVerifyDataFailed(self, data):
        #TODO
        logging.info("Data packet failed verification")

    def onVerifiedInterest(self, data):
        #TODO
        logging.info("Data packet verified")

    def onVerifyInterestFailed(self, data):
        #TODO
        logging.info("Data packet failed verification")

    def requestIdentityBasedPrivateKey(self):
        """
        Setup a local PKG only for this Device to be able to do initialization with a PKG.

        Set the KeyLocator to the ID of the requesting Device.
        Append the TemporaryMasterPublicKey to the Interest.

        Interest:
            Name: /ndn/no/ntnu/initDevice/<nonce>/<tempMasterPublicKey>
            Selector: KeyLocator = ID

        Send the Interest
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
        keyLocator.setKeyName(Name(self.deviceName).append(str(messageBuf_pb2.Message.WATERS09)))
        interest.setKeyLocator(keyLocator)

        logging.info("Expressing interest name: " + name.toUri())
        self.face.expressInterest(interest, self.onInitData, self.onTimeout)

    def onInitData(self, interest, data):
        """
        Data:
            Content: 
                master_public_key to PKG
                ibeKey = ibe(randomKey)
                cipher = encrypt(PrivateKey, randomKey)

        Decrypt the symmetric key with the TemporaryMasterPublicKey and the device ID.
        Use the symmetric key to decrypt the PrivateKey.

        Device is now added to the PKG        
        """
        self.keyChain.verifyData(data, self.onVerifiedData, self.onVerifyDataFailed)
        
        message = messageBuf_pb2.Message()
        message.ParseFromString(data.getContent().toRawStr())

        # TODO: Compare session
        session = message.nonce

        if (message.type == messageBuf_pb2.Message.INIT):
            if (message.encAlgorithm == messageBuf_pb2.Message.AES):
                # Check if IBS algorithm is the same
                if not (self.ibs_scheme.algorithm == message.ibsAlgorithm)
                    logging.error("IBS algorithm doesnt match! Receiver: "+self.ibs_scheme.algorithm+", Sender: "+message.ibsAlgorithm)

                # Check if IBE algorithm is the same
                if not (self.ibe_scheme.algorithm == message.ibeAlgorithm)
                    logging.error("IBE algorithm doesnt match! Receiver: "+self.ibe_scheme.algorithm+", Sender: "+message.ibeAlgorithm)

                #Decrypt identityBasedEncrypedKey
                identityBasedEncryptedKeyDict = ast.literal_eval(message.identityBasedEncryptedKey)
                identityBasedEncryptedKey = deserializeObject(identityBasedEncryptedKeyDict, self.ibe_scheme.group)
                key = self.ibe_scheme.decryptKey(self.temp_master_public_key, self.temp_private_key, identityBasedEncryptedKey)
                
                #Decrypt encryptedMessage
                a = SymmetricCryptoAbstraction(extractor(key))
                keyDict = a.decrypt(message.encryptedMessage)
                # PrivateKeys
                privateKeyEncoded           = keyDict['pk']
                signaturePrivateKeyEncoded  = keyDict['spk']
                self.private_key            = bytesToObject(privateKeyEncoded, self.ibe_scheme.group)
                self.signature_private_key  = bytesToObject(signaturePrivateKeyEncoded, self.ibs_scheme.group)
                
                # SignatureMasterPublicKey
                signatureMasterPublicKeyDict = ast.literal_eval(message.identityBasedSignatureMasterPublicKey)
                self.signature_master_public_key = deserializeObject(signatureMasterPublicKeyDict, self.ibs_scheme.group)

                # MasterPublicKey
                masterPublicKeyDict     = ast.literal_eval(message.identityBasedMasterPublicKey)
                self.master_public_key  = deserializeObject(masterPublicKeyDict, self.ibe_scheme.group)

                logging.info("Initialization success! PrivateKeys, MasterPublicKeys received.")