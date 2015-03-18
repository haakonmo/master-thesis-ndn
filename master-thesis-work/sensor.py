#!/usr/bin/python
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

    def __init__(self, face, keyChain, certificateName):
        self.face = face
        self.keyChain = keyChain
        self.certificateName = certificateName

        name = Name("/ndn/no/ntnu/sensor_pull")
        util.dump("Expressing interest name: ", name.toUri())
        self.face.expressInterest(name, self.onData, self.onTimeout)

    def onInterest(self, prefix, interest, transport, registeredPrefixId):
        util.dumpInterest(interest)

    def onData(self, interest, data):
        util.dumpData(data)

    def onTimeout(self, interest):
        util.dump("Time out for interest", interest.getName().toUri())

    def onRegisterFailed(self, prefix):
        util.dump("Register failed for prefix", prefix.toUri())

class SensorData(object):

    def __init__(self, face, keyChain, certificateName):
        self.face = face
        self.keyChain = keyChain
        self.certificateName = certificateName

        prefix = Name("/ndn/no/ntnu/sensor_pull")
        util.dump("Register prefix", prefix.toUri())
        self.face.registerPrefix(prefix, self.onInterest, self.onRegisterFailed)

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
        util.dumpData(data)

    def onTimeout(self, interest):
        util.dump("Time out for interest", interest.getName().toUri())

    def onRegisterFailed(self, prefix):
        util.dump("Register failed for prefix", prefix.toUri())