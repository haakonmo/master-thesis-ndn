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

def onData(interest, data):
    util.dump("Data received: ", interest.getName().toUri())
    util.dumpData(data)

def onTimeout(interest):
    util.dump("Time out for interest", interest.getName().toUri())

def main():
    logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

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
    
main()