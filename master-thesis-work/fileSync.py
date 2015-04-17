#!/usr/bin/python
import fileSyncBuf_pb2
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
from pyndn.sync import ChronoSync2013

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from watchdog.events import FileModifiedEvent

class FileSync(object):
    def __init__(self, screenName, fileFolderName, hubPrefix, face, keyChain, certificateName, path):
        """
        FileSync:
            To be written (TBW)

        """
        self.screenName = screenName
        self.fileFolderName = fileFolderName
        self.path = path
        # ChronoSync2013: The Face for calling registerPrefix and expressInterest. 
        # The Face object must remain valid for the life of this ChronoSync2013 object.
        self.face = face
        self.keyChain = keyChain
        self.certificateName = certificateName

        self.syncDataCache = [] # of CachedSyncData
        self.roster = [] # of str (list of all nodes that are subscribing)
        self.maxDataCacheLength = 100
        self.isRecoverySyncState = True
        self.syncLifetime = 15000.0 # milliseconds

        # This should only be called once, so get the random string here.
        self.fileFolderPrefix = Name(hubPrefix).append(self.fileFolderName).append(self.getRandomString())

        # ChronoSync2013: The session number used with the applicationDataPrefix in sync state messages.
        session = int(round(self.getNowMilliseconds() / 1000.0)) 

        self.userName = self.screenName + str(session)
        
        broadcastPrefix = Name("/ndn/broadcast/FileSync-0.1").append(self.fileFolderName)
        self.sync = ChronoSync2013(
           self.sendInterest,               #onReceivedSyncState        (function object)
           self.initial,                    #onInitialized              (function object)
           self.fileFolderPrefix,           #applicationDataPrefix      (Name)
           broadcastPrefix,                 #applicationBroadcastPrefix (Name)
           session,                         #sessionNo                  (int)
           self.face,                       #face                       (Face)
           self.keyChain,                   #KeyChain                   (KeyChain)
           self.certificateName,            #certificateName            (Name)
           self.syncLifetime,               #syncLifetime               (float)
           self.onRegisterFailed)           #onRegisterFailed           (function object)

        face.registerPrefix(self.fileFolderPrefix, self.onInterest, self.onRegisterFailed)

    def onFileUpdate(self, data):
        """
        FileSync:
            When a key pair is edited, i.e. renewed, the application will publish a new sequence number in ChronoSync2013

        """
        # When the application wants to publish data, it calls ChronoSync2013 method publishNextSequenceNo()

        #Subscribe to "file folder" if not subscribing already
        if len(self.syncDataCache) == 0:
            self.syncDataCacheAppend(fileSyncBuf_pb2.FileSync.SUBSCRIBE, "xxx")

        #TODO: check wether the new public key is new.
        self.sync.publishNextSequenceNo()
        self.syncDataCacheAppend(fileSyncBuf_pb2.FileSync.UPDATE, data)

    def unsubscribe(self):
        """
        FileSync:
            Send the unsubscribe message and unsubscribe the public key.
        """
        self.sync.publishNextSequenceNo()
        self.syncDataCacheAppend(fileSyncBuf_pb2.FileSync.UNSUBSCRIBE, "xxx")

    # onInitialized
    def initial(self):
        """
        FileSync:
            To be written (TBW)

        ChronoSync2013 docs: 
        onInitialized: 
            This calls onInitialized() when the first sync data is received 
            (or the interest times out because there are no other publishers yet).
        """
        timeout = Interest(Name("/local/timeout"))
        timeout.setInterestLifetimeMilliseconds(60000)
        self.face.expressInterest(timeout, self.dummyOnData, self.onTimeout)

        try:
            self.roster.index(self.userName)
        except ValueError:
            self.roster.append(self.userName)
            print("Member: " + self.screenName)
            print(self.screenName + ": Subscribe")
            self.syncDataCacheAppend(fileSyncBuf_pb2.FileSync.SUBSCRIBE, "xxx")

    # onReceivedSyncState
    def sendInterest(self, syncStates, isRecovery):
        """
        FileSync:
            To be written (TBW)

        ChronoSync2013 docs:
        onReceivedSyncState: 
            When ChronoSync receives a sync state message, this calls onReceivedSyncState(syncStates, isRecovery) 
            where syncStates is the list of SyncState messages and isRecovery is true if this is the initial list of SyncState 
            messages or from a recovery interest. (For example, if isRecovery is true, a chat application would not 
            want to re-display all the associated chat messages.) The callback should send interests to fetch the application 
            data for the sequence numbers in the sync state.
        """
        self.isRecoverySyncState = isRecovery
        util.dump("onReceivedSyncState in recovery: ", self.isRecoverySyncState)

        sendList = []       # of str
        sessionNoList = []  # of int
        sequenceNoList = [] # of int
        # Loops through the syncStates
        # ChronoSync2013: A SyncState holds the values of a sync state message which is passed to the 
        #     onReceivedSyncState callback which was given to the ChronoSync2013 constructor.
        for j in range(len(syncStates)):
            syncState = syncStates[j]

            # ChronoSync2013: Get the application data prefix for this sync state message.
            nameComponents = Name(syncState.getDataPrefix())

            #TODO not used..
            tempName = nameComponents.get(-1).toEscapedString()
            # tempName is the random string 
            # ChronoSync2013: Get the sequence number for this sync state message.
            sequenceNo = syncState.getSequenceNo()
            # ChronoSync2013: Get the session number associated with the application data prefix for this sync state message.
            sessionNo = syncState.getSessionNo()

            #Loop through sendList for not adding duplcates
            index = -1
            for k in range(len(sendList)):
                if sendList[k] == syncState.getDataPrefix():
                    index = k
                    break
            if index != -1:
                sessionNoList[index] = sessionNo
                sequenceNoList[index] = sequenceNo
            else:
                #append to sendList for sending out interest
                sendList.append(syncState.getDataPrefix())
                sessionNoList.append(sessionNo)
                sequenceNoList.append(sequenceNo)

        # Loop through all syncStates and send an interest for all. 
        for i in range(len(sendList)):
            uri = (sendList[i] + "/" + str(sessionNoList[i]) + "/" + str(sequenceNoList[i]))
            interestName = Name(uri)
            util.dump("Sync - sending interest: ", interestName.toUri())

            interest = Interest(interestName)
            interest.setInterestLifetimeMilliseconds(self.syncLifetime)
            self.face.expressInterest(interest, self.onData, self.onTimeout)

    def onInterest(self, prefix, interest, transport, registeredPrefixId):
        """
        FileSync:
            To be written (TBW)

        """
        util.dump("Got interest packet with name", interest.getName().toUri())
        util.dumpInterest(interest)
        
        content = fileSyncBuf_pb2.FileSync()
        sequenceNo = int(
            interest.getName().get(self.fileFolderPrefix.size() + 1).toEscapedString())
        gotContent = False
        
        #loop through all cached data and find out if you have some new content to respond with
        for i in range(len(self.syncDataCache) - 1, -1, -1):
            data = self.syncDataCache[i]
            if data.sequenceNo == sequenceNo:
                if data.dataType != fileSyncBuf_pb2.FileSync.UPDATE:
                    # Use setattr because "from" is a reserved keyword.
                    setattr(content, "from", self.screenName)
                    content.to              = self.fileFolderName
                    content.dataType        = data.dataType
                    content.timestamp       = int(round(data.time / 1000.0))
                else:
                    setattr(content, "from", self.screenName)
                    content.to              = self.fileFolderName
                    content.dataType        = data.dataType
                    content.data            = data.data
                    content.timestamp       = int(round(data.time / 1000.0))
                gotContent = True
                break
        
        if gotContent:
            logging.info("new content!")
            #Serialize the pklistbuf
            array = content.SerializeToString()
            #Initialize the data with Name
            data = Data(interest.getName())
            #Set content for the data --> the serialized content to bytes
            data.setContent(Blob(array))
            #Add sign the data
            self.keyChain.sign(data, self.certificateName)
            try:
                transport.send(data.wireEncode().toBuffer())
            except Exception as ex:
                logging.getLogger(__name__).error(
                "Error in transport.send: %s", str(ex))
                return
        

    def onData(self, interest, data):
        """
        FileSync:
            To be written (TBW)

        """
        # TODO: Verify packet
        self.keyChain.verifyData(data, self.onVerified, self.onVerifyFailed)

        util.dump("Got data packet with name", data.getName().toUri())
        util.dumpData(data)

        content = fileSyncBuf_pb2.FileSync()
        content.ParseFromString(data.getContent().toRawStr())
        print("Type: " + str(content.dataType) + ", data: "+content.data)

        if self.getNowMilliseconds() - content.timestamp * 1000.0 < 120000.0:
            # Use getattr because "from" is a reserved keyword.
            name = getattr(content, "from")
            prefix = data.getName().getPrefix(-2).toUri()
            sessionNo = int(data.getName().get(-2).toEscapedString())
            sequenceNo = int(data.getName().get(-1).toEscapedString())
            nameAndSession = name + str(sessionNo)


            l = 0
            # Update roster.
            while l < len(self.roster):
                entry = self.roster[l]
                tempName = entry[0:len(entry) - 10]
                tempSessionNo = int(entry[len(entry) - 10:])
                if (name != tempName and
                    content.dataType != fileSyncBuf_pb2.FileSync.UNSUBSCRIBE):
                    l += 1
                else:
                    if name == tempName and sessionNo > tempSessionNo:
                        self.roster[l] = nameAndSession
                    break

            if l == len(self.roster):
                self.roster.append(nameAndSession)
                print(name + ": Subscribe")


            # Use getattr because "from" is a reserved keyword.
            if (content.dataType == fileSyncBuf_pb2.FileSync.UPDATE and
                not self.isRecoverySyncState and getattr(content, "from") != self.screenName):
                self.onRecievedFileUpdate(content)
            elif content.dataType == fileSyncBuf_pb2.FileSync.UNSUBSCRIBE:
                # leave message
                try:
                    n = self.roster.index(nameAndSession)
                    if name != self.screenName:
                        self.roster.pop(n)
                        print(name + ": Unsubscribe")
                except ValueError:
                    pass

    def onVerified(self, data):
        #TODO
        print("Data packet verified")

    def onVerifyFailed(self, data):
        #TODO
        print("Data packet failed verification")

    def onRecievedFileUpdate(self, content):
        print(getattr(content, "from") + ": " + content.data)
        fileName = self.path + getattr(content, "from")
        if (os.path.isfile(fileName)):
            # update file
            logging.info("Updating file" + fileName)
            fileTemp = open(fileName, 'r+')
            fileTemp.write(content.data)
            fileTemp.close()
        else:
            # create file
            logging.info("Creating file" + fileName)
            fileTemp = open(fileName, "w")
            fileTemp.write(content.data)
            fileTemp.close()

    def onRegisterFailed(prefix):
        print("Register failed for prefix " + prefix.toUri())

    def heartbeat(self, interest):
        """
        This repeatedly calls itself after a timeout to send a heartbeat message
        (pksync message type HELLO). This method has an "interest" argument
        because we use it as the onTimeout for Face.expressInterest.
        """
        if len(self.syncDataCache) == 0:
            self.syncDataCacheAppend(fileSyncBuf_pb2.FileSync.SUBSCRIBE, "xxx")

        self.sync.publishNextSequenceNo()
        self.syncDataCacheAppend(fileSyncBuf_pb2.FileSync.HELLO, "xxx")

        # Call again.
        # TODO: Are we sure using a "/local/timeout" interest is the best future call
        # approach?
        timeout = Interest(Name("/local/timeout"))
        timeout.setInterestLifetimeMilliseconds(60000)
        self.face.expressInterest(timeout, self.dummyOnData, self.heartbeat)

    def onTimeout(self, interest):
        """
        FileSync:
            To be written (TBW)
        """
        util.dump("Time out for interest", interest.getName().toUri())

    def syncDataCacheAppend(self, dataType, data):
        """
        FileSync:
            To be written (TBW)

        ChronoChat:
            Append a new CachedMessage to messageCache_, using given messageType and
            message, the sequence number from _sync.getSequenceNo() and the current
            time. Also remove elements from the front of the cache as needed to keep
            the size to _maxMessageCacheLength.
        """
        cachedData = self.CachedData(self.sync.getSequenceNo(), dataType, data, self.getNowMilliseconds())

        self.syncDataCache.append(cachedData)

        while len(self.syncDataCache) > self.maxDataCacheLength:
            self.syncDataCache.pop(0)

    @staticmethod
    def getNowMilliseconds():
        """
        Get the current time in milliseconds.
        
        :return: The current time in milliseconds since 1/1/1970, including fractions of a millisecond.
        :rtype: float
        """
        return time.time() * 1000.0

    @staticmethod
    def getRandomString():
        """
        Generate a random name for ChronoSync.
        """
        #TODO: better seed
        seed = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789"
        result = ""
        for i in range(10):
            # Using % means the distribution isn't uniform, but that's OK.
            position = random.randrange(256) % len(seed)
            result += seed[position]

        return result


    @staticmethod
    def dummyOnData(interest, data):
        """
        This is a do-nothing onData for using expressInterest for timeouts.
        This should never be called.
        """
        pass

    class CachedData(object):
        def __init__(self, sequenceNo, dataType, data, time):
            self.sequenceNo = sequenceNo
            self.dataType = dataType
            self.data = data
            self.time = time


class FileWatch(FileSystemEventHandler):
    def __init__(self, watcher, path):
        self.watcher = watcher
        self.observer = Observer()
        self.observer.schedule(self, path, recursive=True)
        self.observer.start()

    def stopFileWatch(self):
        self.observer.stop()
        self.observer.join()

    def on_any_event(self, event):
        """Catch-all event handler.

        :param event:
            The event object representing the file system event.
        :type event:
            :class:`FileSystemEvent`
        """

    def on_moved(self, event):
        """Called when a file or a directory is moved or renamed.

        :param event:
            Event representing file/directory movement.
        :type event:
        :class:`DirMovedEvent` or :class:`FileMovedEvent`
        """

    def on_created(self, event):
        """Called when a file or directory is created.

        :param event:
            Event representing file/directory creation.
        :type event:
            :class:`DirCreatedEvent` or :class:`FileCreatedEvent`
        """

    def on_deleted(self, event):
        """Called when a file or directory is deleted.

        :param event:
            Event representing file/directory deletion.
        :type event:
            :class:`DirDeletedEvent` or :class:`FileDeletedEvent`
        """

    def on_modified(self, event):
        """Called when a file or directory is modified.

        :param event:
            Event representing file/directory modification.
        :type event:
            :class:`DirModifiedEvent` or :class:`FileModifiedEvent`
        """
        if not event.is_directory:
            logging.info("A file changed:" + event.src_path)
            fileTemp = open(str(event.src_path), 'r')
            fileTempData = fileTemp.read()
            self.watcher.onFileUpdate(fileTempData)
            fileTemp.close()