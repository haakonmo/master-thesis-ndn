#!/usr/bin/python3
import messageBuf_pb2
import logging
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

from keyGeneration import IbeWaters09

class PublicKeyGenerator(object):

    def __init__(self, face, keyChain, certificateName, baseName):
        self.ibeScheme = IbeWaters09()

        (master_public_key, master_secret_key) = self.ibeScheme.setup()
        self.master_public_key = master_public_key
        self.master_secret_key = master_secret_key
        self.face = face
        self.keyChain = keyChain
        self.certificateName = certificateName

        self.baseName = Name(baseName)
        self.prefix = Name(baseName).append("pkg").append("initDevice")
        logging.info("PKG: Register prefix " + self.prefix.toUri())
        self.face.registerPrefix(self.prefix, self.onInitInterest, self.onRegisterFailed)

        self.prefix = Name(baseName).append("pkg")
        logging.info("PKG: Register prefix " + self.prefix.toUri())
        self.face.registerPrefix(self.prefix, self.onInterest, self.onRegisterFailed)

    def onInitInterest(self, prefix, interest, transport, registeredPrefixId):
        """
        extract privateKey
        encrypt privateKey
        send encrypted message and master_public_key
        """
        ID = ""
        if interest.getKeyLocator().getType() == KeyLocatorType.KEYNAME:
            ID = interest.getKeyLocator().getKeyName().toUri()
        logging.info("Extracting private key for ID: " + ID)

        device_private_key = self.ibeScheme.extract(self.master_public_key, self.master_secret_key, ID)

        data = Data(interest.getName())
        
        message = messageBuf_pb2.Message()
        #set masterPublicKey
        # util.parse_dict(message, self.master_public_key)
        message.identityBasedMasterPublicKey = str(serializeObject(self.master_public_key, self.ibeScheme.group))
        #TODO private key MUST be encrypted somehow..
        message.encryptedMessage = str(serializeObject(device_private_key, self.ibeScheme.group))
        message.encryptionType = messageBuf_pb2.Message.NONE
        message.timestamp = int(round(util.getNowMilliseconds() / 1000.0)) 
        message.type = messageBuf_pb2.Message.INIT
        
        content = message.SerializeToString()
        data.setContent(Blob(content))
        self.keyChain.sign(data, self.certificateName)
        encodedData = data.wireEncode()

        logging.info("Sent InitResponse")
        transport.send(encodedData.toBuffer())

    def onInterest(self, prefix, interest, transport, registeredPrefixId):
        util.dumpInterest(interest)

    def onData(self, interest, data):

        util.dumpData(data)

    def onTimeout(self, interest):
        util.dump("Time out for interest", interest.getName().toUri())

    def onRegisterFailed(self, prefix):
        util.dump("Register failed for prefix", prefix.toUri())