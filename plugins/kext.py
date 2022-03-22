__author__ = "patrick w"

"""
kernel extensions (kexts)

    kexts are modules that are loaded by OS X to execute within ring-0 (the kernel)

    this plugin reads all plists within the OS's kexts directories and extracts all referened kernel binaries
"""

import glob

# plugin framework import
from yapsy.IPlugin import IPlugin

# project imports
from knockknock import file, utils

# directories where kexts live
KEXT_DIRECTORIES = ["/System/Library/Extensions/", "/Library/Extensions/"]

# for output, item name
KEXT_NAME = "Kernel Extensions"

# for output, description of items
KEXT_DESCRIPTION = "Modules that are loaded into the kernel"

# plugin class
class scan(IPlugin):

    # init results dictionary
    # ->item name, description, and list
    def initResults(self, name, description):

        # results dictionary
        return {"name": name, "description": description, "items": []}

    # invoked by core
    def scan(self):

        # kexts
        kexts = []

        # dbg
        utils.logMessage(utils.MODE_INFO, "running scan")

        # init results dictionary
        results = self.initResults(KEXT_NAME, KEXT_DESCRIPTION)

        # get all files in kext directories
        for kextDir in KEXT_DIRECTORIES:

            # dbg
            utils.logMessage(utils.MODE_INFO, "scanning %s" % kextDir)

            # get kexts
            kexts.extend(glob.glob(kextDir + "*"))

        # process
        # ->gets kext's binary, then create file object and add to results
        for kextBundle in kexts:

            # skip kext bundles that don't have kext's
            if not utils.getBinaryFromBundle(kextBundle):

                # next!
                continue

            # create and append
            # ->pass bundle, since want to access info.plist, etc
            results["items"].append(file.File(kextBundle))

        return results
