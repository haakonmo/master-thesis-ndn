import sys
import logging
import time
import random
import select
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
from pyndn.sync import ChronoSync2013

class PublicKeySync(object):
	#pkList == chatRomm
	def __init__(self, screenName, pkList, hubPrefix, face, keyChain, certificateName):
		self._screenName = screenName
		self._pkList = pkList
		self._face = face
		self._keyChain = keyChain
		self._certificateName = certificateName

		self._messageCache = [] # of CachedMessage
		self._roster = [] # of str
		self._maxMessageCacheLength = 100
		self._isRecoverySyncState = True
		self._syncLifetime = 5000.0 # milliseconds

        # This should only be called once, so get the random string here.
		self._pkListPrefix = Name(hubPrefix).append(self._pkList).append(self._getRandomString())
		session = int(round(self.getNowMilliseconds() / 1000.0))
		self._userName = self._screenName + str(session)
        
		self._sync = ChronoSync2013(
           self._sendInterest, 
           self._initial, 
           self._pkListPrefix,
           Name("/ndn/broadcast/PublicKeySync-0.1").append(self._pkList), 
           session,
           face, 
           keyChain, 
           certificateName, 
           self._syncLifetime,
           onRegisterFailed)

		face.registerPrefix(self._pkListPrefix, self._onInterest, onRegisterFailed)

def onRegisterFailed(prefix):
    print("Register failed for prefix " + prefix.toUri())

def promptAndInput(prompt):
    if sys.version_info[0] <= 2:
        return raw_input(prompt)
    else:
        return input(prompt)
        
def main():
	screenName = promptAndInput("Enter your name: ")

	defaultHubPrefix = "ndn/edu/ucla/remap"
	hubPrefix = promptAndInput("Enter your hub prefix [" + defaultHubPrefix + "]: ")
	if hubPrefix == "":
		hubPrefix = defaultHubPrefix

	defaultpkList = "ntnu"
	pkList = promptAndInput("Enter the name you want to sync public key list with [" + defaultpkList + "]: ")
	if pkList == "":
		pkList = defaultpkList

	host = "localhost"
	print("Connecting to " + host + ", Public Key List: " + pkList + ", Name: " + screenName)
	print("")

    # Set up the key chain.
	face = Face(host)

	identityStorage = MemoryIdentityStorage()
	privateKeyStorage = MemoryPrivateKeyStorage()
	keyChain = KeyChain(IdentityManager(identityStorage, privateKeyStorage),
                        NoVerifyPolicyManager())
	keyChain.setFace(face)
	keyName = Name("/testname/DSK-123")
	certificateName = keyName.getSubName(0, keyName.size() - 1).append(
      "KEY").append(keyName[-1]).append("ID-CERT").append("0")
	identityStorage.addKey(keyName, KeyType.RSA, Blob(DEFAULT_RSA_PUBLIC_KEY_DER))
	privateKeyStorage.setKeyPairForKeyName(
      keyName, KeyType.RSA, DEFAULT_RSA_PUBLIC_KEY_DER, DEFAULT_RSA_PRIVATE_KEY_DER)
	face.setCommandSigningInfo(keyChain, certificateName)

	pkSyns = PublicKeySync(
      screenName, pkList, Name(hubPrefix), face, keyChain, certificateName)

main()
