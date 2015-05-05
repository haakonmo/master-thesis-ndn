#!/usr/bin/python
import ast
import messageBuf_pb2

from Crypto.Hash import SHA256
from pyndn.name import Name
from pyndn.data import Data
from pyndn.util.change_counter import ChangeCounter
from pyndn.util.common import Common
from pyndn.util.blob import Blob
from pyndn.encoding import WireFormat
from pyndn.key_locator import KeyLocator, KeyLocatorType
from pyndn.security.security_types import DigestAlgorithm
from pyndn.signature import Signature

from charm.core.engine.util import serializeObject, deserializeObject, objectToBytes, bytesToObject

# all ID-based encryption schemes implemented in Charm
#from charm.schemes.ibenc.ibenc_bb03 import IBE_BB04
#from charm.schemes.ibenc.ibenc_ckrs09 import IBE_CKRS
#from charm.schemes.ibenc.ibenc_lsw08 import IBE_Revoke
#from charm.schemes.ibenc.ibenc_sw05 import IBE_SW05

from charm.toolbox.pairinggroup import PairingGroup,GT
from charm.toolbox.hash_module import Waters,Hash,int2Bytes,integer
from charm.schemes.ibenc.ibenc_waters09 import DSE09
from charm.schemes.ibenc.ibenc_waters05 import IBE_N04
from charm.schemes.pksig.pksig_waters import WatersSig

class IbeWaters09(object):

    def __init__(self):
        self.group = PairingGroup('SS512')
        self.ibe = DSE09(self.group)
        self.algorithm = messageBuf_pb2.Message.WATERS09

    def setup(self):
        return self.ibe.setup()

    def extract(self, master_public_key, master_secret_key, ID):
        secret_key = self.ibe.keygen(master_public_key, master_secret_key, ID)
        return secret_key

    def getRandomKey(self):
        key = self.group.random(GT)
        return key

    def encryptKey(self, master_public_key, ID, key):
        cipher_key = self.ibe.encrypt(master_public_key, key, ID)
        return cipher_key

    def decryptKey(self, master_public_key, secret_key, cipher):
        # master_public_key not used
        key = self.ibe.decrypt(cipher, secret_key)
        return key

class IbsWaters09(object):

    def __init__(self):
        self.group = PairingGroup('SS512')
        self.water = WatersSig(group)

    def setup(self):
        return self.water.setup(5)

    def extract(self, master_public_key, master_secret_key, ID):
        secret_key = self.water.keygen(master_public_key, master_secret_key, ID)
        return secret_key

    def signInterest(self, master_public_key, secret_key, ID, interest, wireFormat = None):
        """
        Append a SignatureInfo to the Interest name, sign the name components
        and append a final name component with the signature bits.

        :param master_public_key
        :param secret_key
        :param ID
        :param Interest interest: The Interest object to be signed. This appends
          name components of SignatureInfo and the signature bits.
        :param wireFormat: (optional) A WireFormat object used to encode the
           input. If omitted, use WireFormat.getDefaultWireFormat().
        :type wireFormat: A subclass of WireFormat
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        digestAlgorithm = [0]
        signature = Sha256WithIbsWaters09Signature()
        digestAlgorithm[0] = DigestAlgorithm.SHA256
        signature.getKeyLocator().setType(KeyLocatorType.KEYNAME)
        signature.getKeyLocator().setKeyName(ID)

        # Append the encoded SignatureInfo.
        interest.getName().append(wireFormat.encodeSignatureInfo(signature))

        # Encode once to get the signed portion, and sign.
        encoding = interest.wireEncode(wireFormat)


        signature.setSignature(self._privateKeyStorage.sign
          (encoding.toSignedBuffer(),
           self.certificateNameToPublicKeyName(certificateName),
           digestAlgorithm[0]))

        # Remove the empty signature and append the real one.
        interest.setName(interest.getName().getPrefix(-1).append(
          wireFormat.encodeSignatureValue(signature)))

        signature = self.water.sign(master_public_key, secret_key, message)
        return signature

    def signData(self, master_public_key, secret_key, data, wireFormat = None):

        signature = self.water.sign(master_public_key, secret_key, message)
        return signature

    def verifyInterest(self, master_public_key, ID, interest, signature):
        verified = self.water.verify(master_public_key, ID, message, signature)
        return verified

    def verifyData(self, master_public_key, ID, data, signature):
        verified = self.water.verify(master_public_key, ID, message, signature)
        return verified

class Sha256WithIbsWaters09Signature(signature):

    """
    Create a new Sha256WithIbsWaters09Signature object, possibly copying values from
    another object.

    :param value: (optional) If value is a Sha256WithIbsWaters09Signature, copy its
      values.  If value is omitted, the keyLocator is the default with
      unspecified values and the signature is unspecified.
    :param value: Sha256WithIbsWaters09Signature
    """
    def __init__(self, value = None):

        if value == None:
            self._keyLocator = ChangeCounter(KeyLocator())
            self._signature = Blob()
        elif type(value) is IbsWaters09Signature:
            # Copy its values.
            self._keyLocator = ChangeCounter(KeyLocator(value.getKeyLocator()))
            self._signature = value._signature
        else:
            raise RuntimeError(
              "Unrecognized type for Sha256WithIbsWaters09Signature constructor: " +
              str(type(value)))

        self._changeCount = 0

    # signature methods:

    def clone(self):
        """
        Create a new Sha256WithIbsWaters09Signature which is a copy of this signature.

        :return: A new object which is a copy of this object.
        :rtype: Sha256WithIbsWaters09Signature
        """
        return Sha256WithIbsWaters09Signature(self)

    def getSignature(self):
        """
        Get the data packet's signature bytes.

        :return: The signature bytes as a Blob, which maybe isNull().
        :rtype: Blob
        """
        return self._signature

    def setSignature(self, signature):
        """
        Set the signature bytes to the given value.

        :param signature: The array with the signature bytes. If signature is
          not a Blob, then create a new Blob to copy the bytes (otherwise
          take another pointer to the same Blob).
        :type signature: A Blob or an array type with int elements
        """
        self._signature = (signature if type(signature) is Blob
                           else Blob(signature))
        self._changeCount += 1

    def getKeyLocator(self):
        """
        Get the key locator.

        :return: The key locator.
        :rtype: KeyLocator
        """
        return self._keyLocator.get()

    def setKeyLocator(self, keyLocator):
        """
        Set the key locator to a copy of the given keyLocator.

        :param KeyLocator keyLocator: The KeyLocator to copy.
        """
        self._keyLocator.set(KeyLocator(keyLocator))
        self._changeCount += 1

    def clear(self):
        self._keyLocator.get().clear()
        self._signature = Blob()
        self._changeCount += 1

    def getChangeCount(self):
        """
        Get the change count, which is incremented each time this object
        (or a child object) is changed.

        :return: The change count.
        :rtype: int
        """
        # Make sure each of the checkChanged is called.
        changed = self._keyLocator.checkChanged()
        if changed:
            # A child object has changed, so update the change count.
            self._changeCount += 1

        return self._changeCount

"""Implementation of David Naccahe Identity Based Encryption"""
class IbeWaters05(object):

    def __init__(self):
        self.group = PairingGroup('SS512')
        self.waters_hash = Waters(group)
        self.ibe = IBE_N04(self.group)
        self.algorithm = messageBuf_pb2.Message.WATERS05

    def setup(self):
        return self.ibe.setup()

    def extract(self, master_public_key, master_secret_key, ID):
        # master_public_key not used
        kID = waters_hash.hash(ID)
        secret_key = self.ibe.extract(master_secret_key, kID)
        return secret_key

    def getRandomKey(self):
        key = self.group.random(GT)
        return key

    def encryptKey(self, master_public_key, ID, key):
        kID = waters_hash.hash(ID)
        cipher_key = self.ibe.encrypt(master_public_key, kID, key)
        return cipher_key

    def decryptKey(self, master_public_key, secret_key, cipher):
        key = self.ibe.decrypt(master_public_key, secret_key, cipher)
        return key


