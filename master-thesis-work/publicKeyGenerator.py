#!/usr/bin/python3
import messageBuf_pb2
import logging
import util
from charm.toolbox.pairinggroup import PairingGroup

# all ID-based encryption schemes implemented in Charm
from charm.schemes.ibenc.ibenc_CW13_z import IBE_CW13
from charm.schemes.ibenc.ibenc_bb03 import IBE_BB04
from charm.schemes.ibenc.ibenc_bf01 import IBE_BonehFranklin
from charm.schemes.ibenc.ibenc_ckrs09 import IBE_CKRS
from charm.schemes.ibenc.ibenc_cllww12_z import IBE_Chen12_z
from charm.schemes.ibenc.ibenc_lsw08 import IBE_Revoke
from charm.schemes.ibenc.ibenc_sw05 import IBE_SW05
from charm.schemes.ibenc.ibenc_waters05 import IBE_N04
from charm.schemes.ibenc.ibenc_waters05_z import IBE_N04_z
from charm.schemes.ibenc.ibenc_waters09 import DSE09
from charm.schemes.ibenc.ibenc_waters09_z import DSE09_z

class PublicKeyGenerator(object):

    def __init__(self, face, keyChain, certificateName, baseName):
        group = PairingGroup('MNT224', secparam=1024)
        ibe = IBE_BonehFranklin(group)
        (self.master_public_key, self.master_secret_key) = ibe.setup()

        self.face = face
        self.keyChain = keyChain
        self.certificateName = certificateName

        self.baseName = Name(baseName)
        self.prefix = self.baseName.append("pkg").append("initDevice")
        logging.info("PKG: Register prefix " + prefix.toUri())
        self.face.registerPrefix(self.prefix, self.onInitInterest, self.onRegisterFailed)

        self.prefix = self.baseName.append("pkg")
        logging.info("PKG: Register prefix " + prefix.toUri())
        self.face.registerPrefix(self.prefix, self.onInterest, self.onRegisterFailed)

    def onInitInterest(self, prefix, interest, transport, registeredPrefixId):
        """
        extract privateKey
        encrypt privateKey
        send encrypted message and master_public_key
        """
        device_private_key = ibe.extract(master_secret_key, ID)

        data = Data(interest.getName())
        
        message = messageBuf_pb2.Message()
        message.master_public_key = master_public_key
        message.data = device_private_key
        message.timestamp = util.getNowMilliseconds()
        
        data.setContent(message)
        self.keyChain.sign(data, self.certificateName)
        encodedData = data.wireEncode()

        transport.send(encodedData.toBuffer())
        logger.info("Sent InitResponse")

    def onInterest(self, prefix, interest, transport, registeredPrefixId):
        util.dumpInterest(interest)

    def onData(self, interest, data):

        util.dumpData(data)

    def onTimeout(self, interest):
        util.dump("Time out for interest", interest.getName().toUri())

    def onRegisterFailed(self, prefix):
        util.dump("Register failed for prefix", prefix.toUri())