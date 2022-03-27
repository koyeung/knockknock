"""kernel extensions (kexts).

kexts are modules that are loaded by OS X to execute within ring-0 (the kernel)
this plugin reads all plists within the OS's kexts directories and extracts
all referened kernel binaries
"""
__author__ = "patrick w"

import glob
import logging

from knockknock import file, utils
from knockknock.plugin_base import KnockKnockPlugin

LOGGER = logging.getLogger(__name__)

# directories where kexts live
KEXT_DIRECTORIES = ["/System/Library/Extensions/", "/Library/Extensions/"]

# for output, item name
KEXT_NAME = "Kernel Extensions"

# for output, description of items
KEXT_DESCRIPTION = "Modules that are loaded into the kernel"


class Scan(KnockKnockPlugin):
    """Plugin class."""

    def scan(self):
        """Scan action."""
        # kexts
        kexts = []

        LOGGER.info("running scan")

        # init results dictionary
        results = self.init_results(KEXT_NAME, KEXT_DESCRIPTION)

        # get all files in kext directories
        for kext_dir in KEXT_DIRECTORIES:

            LOGGER.info("scanning %s", kext_dir)

            # get kexts
            kexts.extend(glob.glob(kext_dir + "*"))

        # process
        # ->gets kext's binary, then create file object and add to results
        for kext_bundle in kexts:

            # skip kext bundles that don't have kext's
            if not utils.get_binary_from_bundle(kext_bundle):

                # next!
                continue

            # create and append
            # ->pass bundle, since want to access info.plist, etc
            results["items"].append(file.File(kext_bundle))

        return results
