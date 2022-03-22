__author__ = "patrick"

import logging
import os
from pathlib import Path

# project imports
from . import utils, whitelist

LOGGER = logging.getLogger(__name__)


class File:

    # init method
    # ->init instance variables, hash file, etc
    def __init__(self, path: str, plist=None, parent=None):

        # init path for bundle
        self.bundle = None

        # if its a directory (e.g. an app bundle)
        # ->get binary (from app's Info.plist)
        if os.path.isdir(path):

            # save bundle path
            self.bundle = path

            # get path
            self.path = utils.getBinaryFromBundle(path)

            # if binary could not be found
            # ->default to 'unknown'
            if not self.path:

                # just set to something...
                self.path = "<unknown>"

        # path is to file
        # ->just save into class var
        else:

            # save
            self.path = path

        # save plist
        # ->this will be set for launch daemons/agents, inserted dylibs, etc
        self.plist = plist

        # compute/save name
        self.name = os.path.split(self.path)[1]

        # compute/save hash
        self.hash = utils.md5sum(self.path)

        # init whitelist flag
        self.isWhitelisted = False

        # check if its whitelisted
        # ->path is key
        if self.path in whitelist.whitelistedFiles:

            # check if hash is in white list
            self.isWhitelisted = self.hash in whitelist.whitelistedFiles[self.path]

        # init
        self.signatureStatus = None

        # init signing authorities
        self.signingAuthorities = None

        # init apple flag
        self.signedByApple = False

        # check file is signed and if so, by apple
        # note: sets class's signatureStatus/signingAuthorities & signedByApple class vars
        self.initSigningStatus()

        # init VT ratio
        self.vtRatio = None

        return

    # return file's path
    def path(self):

        # path
        return self.path

    # return file's name
    def name(self):

        # name
        return self.name

    # return hash
    def hash(self):

        # hash
        return self.hash

    # for normal output
    def prettyPrint(self):

        # certificate info
        signedMsg = ""

        # VT ratio
        vtRatio = ""

        # handle case where hash was unable to be generated
        # ->file wasn't found/couldn't be accessed
        if not self.hash:

            # set some default
            self.hash = "unknown"

        # handle when file is signed
        if 0 == self.signatureStatus:

            # yup
            signedMsg = "yes"

            # add signing auth's
            if len(self.signingAuthorities):

                # add
                signedMsg += " (%s)" % self.signingAuthorities

        # handle when file is not signed
        elif self.signatureStatus:

            # no
            signedMsg = "no (%d)" % self.signatureStatus

        # error case
        # ->couldn't check signature
        else:

            # unknown
            signedMsg = "unknown"

        # non-plisted files
        if not self.plist:

            return "\n%s\n path: %s\n hash: %s\n signed? %s\n VT ratio: %s\n" % (
                self.name,
                self.path,
                self.hash,
                signedMsg,
                self.vtRatio,
            )

        # plisted files
        else:

            return (
                "\n%s\n path: %s\n plist: %s\n hash: %s \n signed? %s\n VT ratio: %s\n"
                % (self.name, self.path, self.plist, self.hash, signedMsg, self.vtRatio)
            )

    # determine if a file (or bundle) is signed, and if so, by Apple
    def initSigningStatus(self):

        # signing info
        signingInfo = {}

        # default path to check as file's path
        path = self.path

        # however for kexts, use their bundle
        # ->this avoids issue with where errSecCSInfoPlistFailed is returned when the kext's binary is checked
        if self.bundle and utils.isKext(self.bundle):

            # set path to bundle
            path = self.bundle

        # check the signature
        if not Path(path).exists():
            LOGGER.warning("path %s not exists", path)
            return

        (status, signingInfo) = utils.checkSignature(path)

        # on success
        # ->save into class var
        if 0 == status:

            # save sig status
            self.signatureStatus = signingInfo["status"]

            # save apple flag
            self.signedByApple = signingInfo["isApple"]

            # save authorities
            self.signingAuthorities = signingInfo["authorities"]

        return
