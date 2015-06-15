#!/usr/bin/python
import messageBuf_pb2
import logging
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

from charm.core.engine.util import serializeObject, deserializeObject
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor
from identityBasedCrypto import IbeWaters09, IbsWaters

class PublicKeyGenerator(object):

    def __init__(self, face, baseName):
        """

        """
        # Devices that are manually approved by an administrator.
        self.approvedDevices = {"/ndn/no/ntnu/device1":Blob("3d58b86f6a302d87881f1af09fd1be3045c0f953"),
                                "/ndn/no/ntnu/device2":Blob("37357ea87ccf6e819754475f0184f961caeb8f28")}

        self.deviceName = Name(baseName).append("pkg")

        #Initialize IBC schemes
        self.ibe_scheme = IbeWaters09()
        self.ibs_scheme = IbsWaters()
        (master_public_key, master_secret_key) = self.ibe_scheme.setup()
        (signature_master_public_key, signature_master_secret_key) = self.ibs_scheme.setup()

        # KeyPair for Identity-Based Encryption
        self.master_public_key = master_public_key
        self.master_secret_key = master_secret_key

        # KeyPair for Identity-Based Signature
        self.signature_master_public_key = signature_master_public_key
        self.signature_master_secret_key = signature_master_secret_key
        self.signature_private_key = self.ibs_scheme.extract(self.signature_master_public_key, self.signature_master_secret_key, self.deviceName.toUri())

        self.face = face

        self.baseName = Name(baseName)
        self.prefix = Name(baseName).append("pkg").append("initDevice")
        logging.info("PKG: Register prefix " + self.prefix.toUri())
        self.face.registerPrefix(self.prefix, self.onInitInterest, self.onRegisterFailed)

        self.prefix = Name(self.deviceName)
        logging.info("PKG: Register prefix " + self.prefix.toUri())
        self.face.registerPrefix(self.prefix, self.onInterest, self.onRegisterFailed)

    def onInitInterest(self, prefix, interest, transport, registeredPrefixId):
        """
        Interest:
            Name: /ndn/no/ntnu/initDevice/<nonce>/<tempMasterPublicKey>
            Selector: KeyLocator = ID

        The ID of the requesting Device is stored in KeyLocator in the Interest, 
        and the TemporaryMasterPublicKey to the device is sent in the Interest Name as shown above.

        Extract the PrivateKey for the ID, and encrypt a symmetric key with the TemporaryMasterPublicKey and the ID.
        Encrypt the PrivateKey with symmetric encryption, using the symmetric key.
        
        Data:
            Content: 
                master_public_key to PKG
                ibeKey = ibe(randomKey)
                cipher = encrypt(PrivateKey, randomKey)

        Sign the Data and send.

        :param Name prefix:
        :param Interest interest:
        :param Transport transport: An object of a subclass of Transport to use for communication.
        :param Name registeredPrefixId:
        """
        ID = ""
        if interest.getKeyLocator().getType() == KeyLocatorType.KEYNAME:
            keyLocator = interest.getKeyLocator().getKeyName()
            tempIbeAlgorithm = int(keyLocator.get(keyLocator.size()-2).toEscapedString())
            tempMasterPublicKeyEncoded = keyLocator.get(keyLocator.size()-1).toEscapedString()
            logging.info(tempMasterPublicKeyEncoded)
            ID = keyLocator.getPrefix(keyLocator.size()-2).toUri()
        
        # Check if ID is in approved devices
        presharedKey = self.approvedDevices[ID]
        if not presharedKey:
            logging.warning("Device " + str(ID) + " is not approved")
        else:
            logging.info("Pre-shared key: " + str(presharedKey))

            # Decrypt cipher
            a = SymmetricCryptoAbstraction(presharedKey)
            message = a.decrypt(cipher)
            decryptedID = message["ID"]
            dectrptedNonce = message["nonce"]

            if not ID == decryptedID:
                logging.warning("Device ID: " + str(decryptedID) + " is not equal to registered ID: " + str(ID))

            # TODO: check the tempIbeAlgorithm for using right ibe_scheme
            logging.info("Extracting PrivateKeys for ID: " + ID)
            device_private_key = self.ibe_scheme.extract(self.master_public_key, self.master_secret_key, ID)
            device_signature_private_key = self.ibs_scheme.extract(self.signature_master_public_key, self.signature_master_secret_key, ID)

            # Encrypt key with the device's temp_master_public_key and ID
            keyName = interest.getName()
            session = keyName.get(keyName.size()-2).toEscapedString()
            
            tempMasterPublicKey = bytesToObject(tempMasterPublicKeyEncoded, self.ibe_scheme.group)
            key = self.ibe_scheme.getRandomKey()
            identityBasedEncryptedKey = self.ibe_scheme.encryptKey(tempMasterPublicKey, ID, key)
            identityBasedEncryptedKey = str(serializeObject(identityBasedEncryptedKey, self.ibe_scheme.group))

            # Symmetric AES encryption of contentData
            encodedPrivateKey = objectToBytes(device_private_key, self.ibe_scheme.group)
            encodedSignaturePrivateKey = objectToBytes(device_signature_private_key, self.ibs_scheme.group)
            # logging.info(encodedPrivateKey)
            # logging.info(encodedSignaturePrivateKey)

            a = SymmetricCryptoAbstraction(extractor(key))
            encryptedPK = a.encrypt(encodedPrivateKey)
            encryptedSPK = a.encrypt(encodedSignaturePrivateKey)
            # logging.info(encryptedPK)
            # logging.info(encryptedSPK)

            responseName = Name(interest.getName())
            logging.info("Response Name: " + responseName.toUri())
            data = Data(responseName)
            message = messageBuf_pb2.Message()
            message.identityBasedMasterPublicKey = str(serializeObject(self.master_public_key, self.ibe_scheme.group))
            message.identityBasedSignatureMasterPublicKey = str(serializeObject(self.signature_master_public_key, self.ibs_scheme.group))
            message.identityBasedEncryptedKey = identityBasedEncryptedKey
            message.encryptedPK = encryptedPK
            message.encryptedSPK = encryptedSPK
            message.encAlgorithm = messageBuf_pb2.Message.AES
            message.ibeAlgorithm = self.ibe_scheme.algorithm
            message.ibsAlgorithm = self.ibs_scheme.algorithm
            message.nonce = session
            message.timestamp = int(round(util.getNowMilliseconds() / 1000.0)) 
            message.type = messageBuf_pb2.Message.INIT
            
            metaInfo = MetaInfo()
            metaInfo.setFreshnessPeriod(10000) # 10 seconds
            content = message.SerializeToString()

            
            data.setContent(Blob(content))
            data.setMetaInfo(metaInfo)
            self.ibs_scheme.signData(self.signature_master_public_key, self.signature_private_key, self.deviceName, data)
            # self.keyChain.sign(data, self.certificateName)
            encodedData = data.wireEncode()
            logging.info(len(encodedData))
            transport.send(encodedData.toBuffer())
            logging.info("Sent Init Data with encrypted Device PrivateKeys")

    def onInterest(self, prefix, interest, transport, registeredPrefixId):
        """
        :param Name prefix:
        :param Interest interest:
        :param Transport transport: An object of a subclass of Transport to use for communication.
        :param Name registeredPrefixId:
        """
        util.dumpInterest(interest)

    def onData(self, interest, data):
        """
        :param Interest interest:
        :param Data data:
        """
        util.dumpData(data)

    def onTimeout(self, interest):
        """
        :param Interest interest:
        """
        logging.info("Time out for interest", interest.getName().toUri())

    def onRegisterFailed(self, prefix):
        """
        :param Name prefix:
        """
        logging.info("Register failed for prefix", prefix.toUri())