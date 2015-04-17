#!/usr/bin/python3
import messageBuf_pb2
import sys
import logging
import time
import random
import os.path
import util
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

class SensorPull(object):

    def __init__(self, face, keyChain, certificateName, baseName):
        self.face = face
        self.keyChain = keyChain
        self.certificateName = certificateName

        self.name = Name(baseName)
        util.dump("Expressing interest name: ", name.toUri())
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
        self.face = face
        self.keyChain = keyChain
        self.certificateName = certificateName

        self.baseName = Name(baseName)
        self.prefix = self.baseName.append("sensor_pull")
        util.dump("Register prefix", prefix.toUri())
        self.face.registerPrefix(self.prefix, self.onInterest, self.onRegisterFailed)

    def onInterest(self, prefix, interest, transport, registeredPrefixId):
        util.dumpInterest(interest)

        data = Data(interest.getName())
        content = "Echo " + interest.getName().toUri()
        data.setContent(content)
        self.keyChain.sign(data, self.certificateName)
        encodedData = data.wireEncode()

        util.dump("Sent content", content)
        transport.send(encodedData.toBuffer())

    def onData(self, interest, data):
        """
        if Message.INIT_RESPONSE then decrypt and store privateKey, store master_public_key
        """
        message = messageBuf_pb2.Message()
        message.ParseFromString(data.getContent().toRawStr())
        if (message.type == Message.INIT_RESPONSE):
            util.dump(message)
            self.privateKey = message.data
            self.master_public_key = message.master_public_key
        

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