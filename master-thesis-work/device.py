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

class SensorPull(object):

    def __init__(self, face, keyChain, certificateName, baseName):
        self.face = face
        self.keyChain = keyChain
        self.certificateName = certificateName

        self.baseName = Name(baseName)
        self.name = Name(baseName).append("sensor_pull")
        util.dump("Expressing interest name: ", self.name.toUri())
        self.face.expressInterest(self.name, self.onData, self.onTimeout)

    def onInterest(self, prefix, interest, transport, registeredPrefixId):
        util.dumpInterest(interest)

    def onData(self, interest, data):
        util.dumpData(data)

    def onTimeout(self, interest):
        util.dump("Time out for interest", interest.getName().toUri())

    def onRegisterFailed(self, prefix):
        util.dump("Register failed for prefix", prefix.toUri())


class SensorData(object):

    def __init__(self, face, keyChain, certificateName, baseName):
        self.group = PairingGroup('MNT224', secparam=1024)
        self.ibe = IBE_BonehFranklin(self.group)

        self.face = face
        self.keyChain = keyChain
        self.certificateName = certificateName

        self.baseName = Name(baseName)
        self.prefix = Name(baseName).append("sensor_pull")
        util.dump("Register prefix", self.prefix.toUri())
        self.face.registerPrefix(self.prefix, self.onInterest, self.onRegisterFailed)

    def onInterest(self, prefix, interest, transport, registeredPrefixId):
        util.dumpInterest(interest)

        data = Data(interest.getName())
        msg = "This should be sensordata"
        ID = interest.getName().toUri()
        logging.info(ID)
        encrypted_msg = self.ibe.encrypt(self.master_public_key, ID, msg)
        encrypted_content = str(serializeObject(encrypted_msg, self.group))
        logging.info(encrypted_content)
        data.setContent(Blob(encrypted_content))
        self.keyChain.sign(data, self.certificateName)
        encodedData = data.wireEncode()

        util.dump("Sent content:", encrypted_content)
        transport.send(encodedData.toBuffer())

    def onData(self, interest, data):
        """
        if Message.INIT_RESPONSE then decrypt and store privateKey, store master_public_key
        """
        message = messageBuf_pb2.Message()
        message.ParseFromString(data.getContent().toRawStr())
        if (message.type == messageBuf_pb2.Message.INIT_RESPONSE):
            privateKeyDict = ast.literal_eval(message.data)
            masterPublicKeyDict = ast.literal_eval(message.masterPublicKey)
            self.private_key = deserializeObject(privateKeyDict, self.group)
            self.master_public_key = deserializeObject(masterPublicKeyDict, self.group)
            logging.info(message.masterPublicKey)
            #self.master_public_key = { str(message.masterPublicKey[0].key) : str(message.masterPublicKey[0].value), 
            #                            str(message.masterPublicKey[1].key) : str(message.masterPublicKey[1].value) }

    def onTimeout(self, interest):
        util.dump("Time out for interest", interest.getName().toUri())

    def onRegisterFailed(self, prefix):
        util.dump("Register failed for prefix", prefix.toUri())

    def requestIdentityBasedPrivateKey(self):
        """
        Create PK/SK for initialization
        Message.INIT 
        send name and PK
        """

        name = self.baseName.append("pkg").append("initDevice")
        util.dump("Expressing interest name: ", name.toUri())
        self.face.expressInterest(name, self.onData, self.onTimeout)