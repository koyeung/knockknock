__author__ = "patrick w"

"""
spotlight importer

    spotlight (mdworker) supports the notion of custom imports (to parse/index custom file formats)

    this plugin enumerates all importers that have been installed in the spotlights 'plugin' directories

"""

import glob
import os

# plugin framework import
from yapsy.IPlugin import IPlugin

# project imports
from knockknock import file, utils

# directories where importers live
IMPORTERS_DIRECTORIES = [
    "/System/Library/Spotlight/",
    "/Library/Spotlight/",
    "~/Library/Spotlight/",
]

# for output, item name
IMPORTER_NAME = "Spotlight Importers"

# for output, description of items
IMPORTER_DESCRIPTION = "Bundles that are loaded by Spotlight (mdworker)"

# plugin class
class scan(IPlugin):

    # init results dictionary
    # ->item name, description, and list
    def initResults(self, name, description):

        # results dictionary
        return {"name": name, "description": description, "items": []}

    # invoked by core
    def scan(self):

        # importers
        importers = []

        # dbg
        utils.logMessage(utils.MODE_INFO, "running scan")

        # init results dictionary
        results = self.initResults(IMPORTER_NAME, IMPORTER_DESCRIPTION)

        # get all files in importer directories
        for importerDir in IMPORTERS_DIRECTORIES:

            # dbg
            utils.logMessage(utils.MODE_INFO, "scanning %s" % importerDir)

            # get imports
            importers.extend(glob.glob(importerDir + "*"))

        # process
        # ->gets bundle's binary, then create file object and add to results
        for importerBundle in importers:

            # skip any non-bundles
            # ->just do a directory check
            if not os.path.isdir(importerBundle):

                # skip
                continue

            # skip any invalid bundles
            if not utils.getBinaryFromBundle(importerBundle):

                # skip
                continue

            # create and append
            # ->pass bundle, since want to access info.plist, etc
            results["items"].append(file.File(importerBundle))

        return results
