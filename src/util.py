#!/usr/bin/python
# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2015 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU Lesser General Public License is in the file COPYING.
import messageBuf_pb2
import logging
import time
from pyndn import Name
from pyndn import Data
from pyndn import ContentType
from pyndn import KeyLocatorType
from pyndn import DigestSha256Signature
from pyndn import Sha256WithRsaSignature
from pyndn.security import KeyType
from pyndn.security import KeyChain
from pyndn.security.identity import IdentityManager
from pyndn.security.identity import MemoryIdentityStorage
from pyndn.security.identity import MemoryPrivateKeyStorage
from pyndn.security.policy import SelfVerifyPolicyManager
from pyndn.util import Blob
from identityBasedCrypto import Sha256WithIbsWatersSignature

def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str else repr(element)) + " "
    print(result)

def dumpData(data):
    dump("name:", data.getName().toUri())
    if data.getContent().size() > 0:
        dump("content (raw):", data.getContent().toRawStr())
        dump("content (hex):", data.getContent().toHex())
    else:
        dump("content: <empty>")
    if not data.getMetaInfo().getType() == ContentType.BLOB:
        dump("metaInfo.type:",
             "LINK" if data.getMetaInfo().getType() == ContentType.LINK
             else "KEY" if data.getMetaInfo().getType() == ContentType.KEY
             else "uknown")
    dump("metaInfo.freshnessPeriod (milliseconds):",
         data.getMetaInfo().getFreshnessPeriod()
         if data.getMetaInfo().getFreshnessPeriod() >= 0 else "<none>")
    dump("metaInfo.finalBlockId:",
         data.getMetaInfo().getFinalBlockId().toEscapedString()
         if data.getMetaInfo().getFinalBlockId().getValue().size() > 0
         else "<none>")
    keyLocator = None
    signature = data.getSignature()
    if type(signature) is Sha256WithRsaSignature:
        dump("Sha256WithRsa signature.signature:",
             "<none>" if signature.getSignature().size() == 0
                      else signature.getSignature().toHex())
        keyLocator = signature.getKeyLocator()
    elif type(signature) is DigestSha256Signature:
        dump("DigestSha256 signature.signature:",
             "<none>" if signature.getSignature().size() == 0
                      else signature.getSignature().toHex())
    elif type(signature) is Sha256WithIbsWatersSignature:
        dump("Sha256WithIbsWatersSignature signature.signature:",
             "<none>" if signature.getSignature().size() == 0
                      else signature.getSignature().toHex())
    if keyLocator != None:
        if keyLocator.getType() != None:
            if (keyLocator.getType() ==
                KeyLocatorType.KEY_LOCATOR_DIGEST):
                dump("signature.keyLocator: KeyLocatorDigest:",
                     keyLocator.getKeyData().toHex())
            elif keyLocator.getType() == KeyLocatorType.KEYNAME:
                dump("signature.keyLocator: KeyName:",
                     keyLocator.getKeyName().toUri())
            else:
                dump("signature.keyLocator: <unrecognized KeyLocatorType")
        else:
            dump("signature.keyLocator: <none>")

def dumpInterest(interest):
    dump("name:", interest.getName().toUri())
    dump("minSuffixComponents:",
         interest.getMinSuffixComponents()
         if interest.getMinSuffixComponents() != None else "<none>")
    dump("maxSuffixComponents:",
         interest.getMaxSuffixComponents()
         if interest.getMaxSuffixComponents() != None else "<none>")
    if interest.getKeyLocator().getType() != None:
        if (interest.getKeyLocator().getType() ==
            KeyLocatorType.KEY_LOCATOR_DIGEST):
            dump("keyLocator: KeyLocatorDigest:",
                 interest.getKeyLocator().getKeyData().toHex())
        elif interest.getKeyLocator().getType() == KeyLocatorType.KEYNAME:
            dump("keyLocator: KeyName:",
                 interest.getKeyLocator().getKeyName().toUri())
        else:
            dump("keyLocator: <unrecognized KeyLocatorType")
    else:
        dump("keyLocator: <none>")
    dump("exclude:",
         interest.getExclude().toUri()
         if interest.getExclude().size() > 0 else "<none>")
    dump("childSelector:",
         interest.getChildSelector()
         if interest.getChildSelector() != None else "<none>")
    dump("mustBeFresh:", interest.getMustBeFresh())
    dump("nonce:", "<none>" if interest.getNonce().size() == 0
                            else interest.getNonce().toHex())
    dump("scope:", "<none>" if interest.getScope() == None
                            else interest.getScope())
    dump("lifetimeMilliseconds:",
         "<none>" if interest.getInterestLifetimeMilliseconds() == None
                  else interest.getInterestLifetimeMilliseconds())

def getNowMilliseconds():
    """
    Get the current time in milliseconds.
    
    :return: The current time in milliseconds since 1/1/1970, including fractions of a millisecond.
    :rtype: float
    """
    return time.time() * 1000.0

def parse_dict(message, values):
    length = len(values)
    for k,v in values.iteritems():
        try:
            pair = message.masterPublicKey.add()
            setattr(pair, "key", k)
            setattr(pair, "value", str(v))
        except AttributeError:
            logging.warning('try to access invalid attributes %r.%r = %r',message,k,v)
