#!/usr/bin/python
import messageBuf_pb2
import sys
import logging
import time
import random
import os.path
import util
import ast
import base64
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

    def __init__(self, face, baseName, deviceName, presharedKey):
        """
        Initialize:
            Identity-Based Encryption scheme
            Identity-Based Signature scheme 

        :param Face face:
        :param Name baseName:
        :param Name deviceName:
        """
        #Initialize IBC schemes
        self.ibe_scheme = IbeWaters09()
        self.ibs_scheme = IbsWaters()

        self.face = face
        
        self.presharedKey = extractor(bytesToObject(presharedKey, self.ibe_scheme.group))

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
        self.dataRequestStart = time.clock()
        # Session used in namePrefix
        session = str(int(round(util.getNowMilliseconds() / 1000.0)))
        self.name = Name(self.baseName).append("device2").append("sensorPull").append(session)
        interest = Interest(self.name)
        self.ibs_scheme.signInterest(self.signature_master_public_key, self.signature_private_key, self.deviceName, interest)

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

        :param Interest interest:
        :param Data data:
        """
        self.ibs_scheme.verifyData(self.signature_master_public_key, data, self.onVerifiedData, self.onVerifyDataFailed)

        message = messageBuf_pb2.Message()
        message.ParseFromString(data.getContent().toRawStr())

        # TODO: compare nonce
        session = message.nonce

        if (message.type == messageBuf_pb2.Message.SENSOR_DATA):
            if (message.encAlgorithm == messageBuf_pb2.Message.AES):

                # Check if IBS algorithm is the same
                if not (self.ibs_scheme.algorithm == message.ibsAlgorithm):
                    logging.error("IBS algorithm doesnt match! Receiver: "+self.ibs_scheme.algorithm+", Sender: "+message.ibsAlgorithm)

                #Compare signature_master_public_key
                signatureMasterPublicKeyDict = ast.literal_eval(message.identityBasedSignatureMasterPublicKey)
                messageSignatureMPK = deserializeObject(signatureMasterPublicKeyDict, self.ibs_scheme.group)
                if not (self.signature_master_public_key == messageSignatureMPK):
                    logging.error("SignatureMasterPulicKey does not match!")

                # Check if IBE algorithm is the same
                if not (self.ibe_scheme.algorithm == message.ibeAlgorithm):
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
                self.dataRequestEnd = time.clock()
                logging.info("Request and receive data time: " + str(self.dataRequestEnd-self.dataRequestStart))

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

        :param Name prefix:
        :param Interest interest:
        :param Transport transport: An object of a subclass of Transport to use for communication.
        :param Name registeredPrefixId:
        """
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
        # Signature Master Public Key
        identityBasedSignatureMasterPublicKey = str(serializeObject(self.signature_master_public_key, self.ibs_scheme.group))
        # Symmetric AES encryption of contentData
        a = SymmetricCryptoAbstraction(extractor(self.key))
        encryptedMessage = a.encrypt(contentData)

        message = messageBuf_pb2.Message()
        message.identityBasedMasterPublicKey = identityBasedMasterPublicKey
        message.identityBasedSignatureMasterPublicKey = identityBasedSignatureMasterPublicKey
        message.identityBasedEncryptedKey = identityBasedEncryptedKey
        message.encryptedMessage = encryptedMessage
        message.encAlgorithm = messageBuf_pb2.Message.AES
        message.ibeAlgorithm = self.ibe_scheme.algorithm
        message.ibsAlgorithm = self.ibs_scheme.algorithm
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
        encodedData = data.wireEncode()

        logging.info("Encrypting with ID: " + ID)
        transport.send(encodedData.toBuffer())
        logging.info("Sent encrypted Data")

    def onRegisterFailed(self, prefix):
        """
        :param Name prefix:
        """
        logging.info("Register failed for prefix" + prefix.toUri())


    # General methods for all devices
    def onTimeout(self, interest):
        """
        :param Interest interest:
        """
        logging.info("Time out for interest" + interest.getName().toUri())

    def onVerifiedData(self, data):
        """
        :param Data data:
        """
        #TODO
        logging.info("Data packet verified")

    def onVerifyDataFailed(self, data):
        """
        :param Data data:
        """
        #TODO
        logging.info("Data packet failed verification")

    def onVerifiedInterest(self, interest):
        """
        :param Interest interest:
        """
        #TODO
        logging.info("Interest packet verified")

    def onVerifyInterestFailed(self, interest):
        """
        :param Interest interest:
        """
        #TODO
        logging.info("Interest packet failed verification")

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
        self.initRequestStart = time.clock()

        ID = self.deviceName.toUri()
        # Make each init unique with a session
        self.initSession = str(int(round(util.getNowMilliseconds() / 1000.0)))

        a = SymmetricCryptoAbstraction(self.presharedKey)
        message = {"ID":ID, "nonce":self.initSession}
        cipher = a.encrypt(str(message))
        cipherEncoded = base64.b64encode(cipher)
        logging.info("Cipher encoded: " + str(cipherEncoded))

        name = Name(self.baseName).append("pkg").append("initDevice").append(self.initSession)
        interest = Interest(name)
        # interest.setMinSuffixComponents(6)
        keyLocator = KeyLocator()
        keyLocator.setType(KeyLocatorType.KEYNAME)
        keyLocator.setKeyName(Name(self.deviceName).append(cipherEncoded))
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
        
        :param Interest interest:
        :param Data data:
        """     
        message = messageBuf_pb2.Message()
        message.ParseFromString(data.getContent().toRawStr())

        # TODO: Compare session
        if not self.initSession == message.nonce:
            logging.warning("Nonce is not equal!")

        # SignatureMasterPublicKey
        signatureMasterPublicKeyDict = ast.literal_eval(message.identityBasedSignatureMasterPublicKey)
        self.signature_master_public_key = deserializeObject(signatureMasterPublicKeyDict, self.ibs_scheme.group)
        # Verify signature
        self.ibs_scheme.verifyData(self.signature_master_public_key, data, self.onVerifiedData, self.onVerifyDataFailed)

        if (message.type == messageBuf_pb2.Message.INIT):
            if (message.encAlgorithm == messageBuf_pb2.Message.AES):
                # Check if IBS algorithm is the same
                if not (self.ibs_scheme.algorithm == message.ibsAlgorithm):
                    logging.error("IBS algorithm doesnt match! Receiver: "+self.ibs_scheme.algorithm+", Sender: "+message.ibsAlgorithm)

                # Check if IBE algorithm is the same
                if not (self.ibe_scheme.algorithm == message.ibeAlgorithm):
                    logging.error("IBE algorithm doesnt match! Receiver: "+self.ibe_scheme.algorithm+", Sender: "+message.ibeAlgorithm)

                #Decrypt encryptedMessage
                # PrivateKeys
                a = SymmetricCryptoAbstraction(self.presharedKey)
                privateKeyEncoded           = a.decrypt(message.encryptedPK)
                signaturePrivateKeyEncoded  = a.decrypt(message.encryptedSPK)
                self.private_key            = bytesToObject(privateKeyEncoded, self.ibe_scheme.group)
                self.signature_private_key  = bytesToObject(signaturePrivateKeyEncoded, self.ibs_scheme.group)
                
                # MasterPublicKey
                masterPublicKeyDict     = ast.literal_eval(message.identityBasedMasterPublicKey)
                self.master_public_key  = deserializeObject(masterPublicKeyDict, self.ibe_scheme.group)

                logging.info("Initialization success! PrivateKeys, MasterPublicKeys received.")
                self.initRequestEnd = time.clock()
                logging.info("Initialization time: " + str(self.initRequestEnd-self.initRequestStart))
