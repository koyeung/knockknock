__author__ = "patrick"

import logging
import os
from pathlib import Path

# project imports
from . import utils, whitelist

LOGGER = logging.getLogger(__name__)


class File:
    """File."""

    # pylint: disable=too-many-instance-attributes

    def __init__(self, path: str, plist=None):
        """init.

        ->init instance variables, hash file, etc
        """
        # init path for bundle
        self.bundle = None

        # if its a directory (e.g. an app bundle)
        # ->get binary (from app's Info.plist)
        if os.path.isdir(path):

            # save bundle path
            self.bundle = path

            # get path
            self.path = utils.get_binary_from_bundle(path)

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
        self.is_whitelisted = False

        # check if its whitelisted
        # ->path is key
        whitelisted_files = whitelist.get_file_whitelist()
        if self.path in whitelisted_files:

            # check if hash is in white list
            self.is_whitelisted = self.hash in whitelisted_files[self.path]

        # init
        self.signature_status = None

        # init signing authorities
        self.signing_authorities = None

        # init apple flag
        self.signed_by_apple = False

        # check file is signed and if so, by apple
        # note: sets class's signatureStatus/signingAuthorities & signedByApple class vars
        self.init_signing_status()

        # init VT ratio
        self.vt_ratio = None

    def pretty_print(self):
        """For normal output."""
        # handle case where hash was unable to be generated
        # ->file wasn't found/couldn't be accessed
        if not self.hash:

            # set some default
            self.hash = "unknown"

        # handle when file is signed
        if self.signature_status == 0:

            # certificate info
            signed_msg = "yes"

            # add signing auth's
            if len(self.signing_authorities):

                # add
                signed_msg += f" ({self.signing_authorities})"

        # handle when file is not signed
        elif self.signature_status:

            # no
            signed_msg = f"no ({self.signature_status})"

        # error case
        # ->couldn't check signature
        else:

            # unknown
            signed_msg = "unknown"

        # non-plisted files
        if not self.plist:
            return f"""
{self.name}
 path: {self.path}
 hash: {self.hash}
 signed? {signed_msg}
 VT ratio: {self.vt_ratio}
"""

        # plisted files
        return f"""
{self.name}
 path: {self.path}
 plist: {self.plist}
 hash: {self.hash}
 signed? {signed_msg}
 VT ratio: {self.vt_ratio}
"""

    def init_signing_status(self):
        """Determin if a file (or bundle) is signed, and if so, by Apple."""
        # signing info
        signing_info = {}

        # default path to check as file's path
        path = self.path

        # however for kexts, use their bundle
        # ->this avoids issue with where errSecCSInfoPlistFailed is returned
        # when the kext's binary is checked
        if self.bundle and utils.is_kext(self.bundle):

            # set path to bundle
            path = self.bundle

        # check the signature
        if not Path(path).exists():
            LOGGER.warning("path %s not exists", path)
            return

        (status, signing_info) = utils.check_signature(path)

        # on success
        # ->save into class var
        if 0 == status:

            # save sig status
            self.signature_status = signing_info["status"]

            # save apple flag
            self.signed_by_apple = signing_info["isApple"]

            # save authorities
            self.signing_authorities = signing_info["authorities"]
