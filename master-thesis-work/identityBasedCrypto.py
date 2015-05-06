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
from pyndn.security.security_exception import SecurityException
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
        signature = makeSignatureByID(ID, digestAlgorithm)

        # Append the encoded SignatureInfo.
        interest.getName().append(wireFormat.encodeSignatureInfo(signature))

        # Append an empty signature so that the "signedPortion" is correct.
        interest.getName().append(Name.Component())
        # Encode once to get the signed portion, and sign.
        encoding = interest.wireEncode(wireFormat)

        ibSignature = self.sign(encoding.toSignedBuffer(), secret_key, ID, digestAlgorithm[0])
        signature.setSignature(ibSignature)

        # Remove the empty signature and append the real one.
        interest.setName(interest.getName().getPrefix(-1).append(
          wireFormat.encodeSignatureValue(signature)))

    def signData(self, master_public_key, secret_key, ID, target, wireFormat = None):
        """
        Sign the target based on the secret_key. If it is a Data object,
        set its signature. If it is an array, return a signature object.

        :param master_public_key
        :param secret_key
        :param ID
        :param target: If this is a Data object, wire encode for signing,
          update its signature and key locator field and wireEncoding. If it is
          an array, sign it and return a Signature object.
        :param wireFormat: (optional) The WireFormat for calling encodeData, or
          WireFormat.getDefaultWireFormat() if omitted.
        :type wireFormat: A subclass of WireFormat
        :return: The Signature object (only if the target is an array).
        :rtype: An object of a subclass of Signature
        """
        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        if isinstance(target, Data):
            data = target
            digestAlgorithm = [0]
            signature = makeSignatureByID(ID, digestAlgorithm)

            data.setSignature(signature)
            # Encode once to get the signed portion.
            encoding = data.wireEncode(wireFormat)

            ibSignature = self.sign(encoding.toSignedBuffer(), secret_key, ID, digestAlgorithm[0])
            data.getSignature().setSignature(ibSignature)

            # Encode again to include the signature.
            data.wireEncode(wireFormat)
        else:
            digestAlgorithm = [0]
            signature = makeSignatureByID(ID, digestAlgorithm)

            ibSignature = self.sign(target, secret_key, ID, digestAlgorithm[0])
            signature.setSignature(ibSignature)

            return signature

    def makeSignatureByID(self, ID, digestAlgorithm):
        signature = Sha256WithIbsWaters09Signature()
        digestAlgorithm[0] = DigestAlgorithm.SHA256
        signature.getKeyLocator().setType(KeyLocatorType.KEYNAME)
        signature.getKeyLocator().setKeyName(ID)
        return signature

    def sign(self, data, secret_key, ID, digestAlgorithm = DigestAlgorithm.SHA256):
        """
        Use the secret key for ID and sign the data, returning a
        signature Blob.

        :param data: Pointer the input byte buffer to sign.
        :type data: An array type with int elements
        :param secret_key: 
        :param Name ID: The Name of the signing key.
        :param digestAlgorithm: (optional) the digest algorithm. If omitted,
          use DigestAlgorithm.SHA256.
        :type digestAlgorithm: int from DigestAlgorithm
        :return: The signature, or an isNull() Blob pointer if signing fails.
        :rtype: Blob
        """

        if secret_key == None:
            raise SecurityException("secret key not found")

        dataStr = Blob(data, False).toRawStr()
        # water.sign() will hash with SHA1, hence no need for digestAlgorithm
        signature = self.water.sign(master_public_key, secret_key, dataStr)
        #signature = self.water.sign(master_public_key, secret_key, SHA256.new(dataStr))
        # base64 signature
        signature = objectToBytes(signature)
        logger.info("Successfully signed packet: " + signature)

        if signature == None:
            raise SecurityException("Signature is NULL!")
        return Blob(bytearray(signature), False)

    def verifyInterest(self, master_public_key, interest, onVerified, onVerifyFailed, stepCount = 0, wireFormat = None):
        """
        Check the signature on the signed interest and call either onVerify or
        onVerifyFailed. We use callback functions because verify may fetch
        information to check the signature.

        :param Interest interest: The interest with the signature to check.
        :param onVerified: If the signature is verified, this calls
          onVerified(interest).
        :type onVerified: function object
        :param onVerifyFailed: If the signature check fails or can't find the
          public key, this calls onVerifyFailed(interest).
        :type onVerifyFailed: function object
        :param int stepCount: (optional) The number of verification steps that
          have been done. If omitted, use 0.
        """
        ID = ""
        if interest.getKeyLocator().getType() == KeyLocatorType.KEYNAME:
            ID = interest.getKeyLocator().getKeyName().toUri()
        else:
            raise SecurityException("Keylocator is not of keyType KEYNAME!")

        keyName = interest.getName()
        session = keyName.get(keyName.size()-2).toEscapedString()
        signature = keyName.get(keyName.size()-1).toEscapedString()
        signature = bytesToObject(signature)
        logger.info("Signature: " + signature)

        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        encoding = interest.wireEncode(wireFormat)
        dataStr = Blob(encoding.toSignedBuffer(), False).toRawStr()
        verified = self.water.verify(master_public_key, ID, dataStr, signature)
        if verified:
            onVerified(interest)
        else:
            onVerifyFailed(interest)

    def verifyData(self, master_public_key, data, onVerified, onVerifyFailed, stepCount = 0, wireFormat = None):
        """
        Check the signature on the Data object and call either onVerify or
        onVerifyFailed. We use callback functions because verify may fetch
        information to check the signature.

        :param Data data: The Data object with the signature to check.
        :param onVerified: If the signature is verified, this calls
          onVerified(data).
        :type onVerified: function object
        :param onVerifyFailed: If the signature check fails or can't find the
          public key, this calls onVerifyFailed(data).
        :type onVerifyFailed: function object
        :param int stepCount: (optional) The number of verification steps that
          have been done. If omitted, use 0.
        """
        ID = ""
        if interest.getKeyLocator().getType() == KeyLocatorType.KEYNAME:
            ID = interest.getKeyLocator().getKeyName().toUri()
        else:
            raise SecurityException("Keylocator is not of keyType KEYNAME!")

        keyName = data.getName()
        session = keyName.get(keyName.size()-1).toEscapedString()
        signature = signature.getSignature()
        signature = Blob(signature, False).toRawStr()
        signature = bytesToObject(signature)
        logger.info("Signature: " + signature)

        if wireFormat == None:
            # Don't use a default argument since getDefaultWireFormat can change.
            wireFormat = WireFormat.getDefaultWireFormat()

        encoding = data.wireEncode(wireFormat)
        dataStr = Blob(encoding.toSignedBuffer(), False).toRawStr()
        verified = self.water.verify(master_public_key, ID, dataStr, signature)
        if verified:
            onVerified(data)
        else:
            onVerifyFailed(data)

class Sha256WithIbsWaters09Signature(Signature):

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


