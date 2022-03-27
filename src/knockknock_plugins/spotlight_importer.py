"""
spotlight importer

    spotlight (mdworker) supports the notion of custom imports (to parse/index custom file formats)

    this plugin enumerates all importers that have been installed in the spotlights
    'plugin' directories

"""
__author__ = "patrick w"

import glob
import logging
import os

from knockknock import file, utils
from knockknock.plugin_base import KnockKnockPlugin

LOGGER = logging.getLogger(__name__)

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


class Scan(KnockKnockPlugin):
    """Plugin class."""

    def scan(self):
        """Scan action."""
        # importers
        importers = []

        LOGGER.info("running scan")

        # init results dictionary
        results = self.init_results(IMPORTER_NAME, IMPORTER_DESCRIPTION)

        # get all files in importer directories
        for importer_dir in IMPORTERS_DIRECTORIES:

            LOGGER.info("scanning %s", importer_dir)

            # get imports
            importers.extend(glob.glob(importer_dir + "*"))

        # process
        # ->gets bundle's binary, then create file object and add to results
        for importer_bundle in importers:

            # skip any non-bundles
            # ->just do a directory check
            if not os.path.isdir(importer_bundle):

                # skip
                continue

            # skip any invalid bundles
            if not utils.get_binary_from_bundle(importer_bundle):

                # skip
                continue

            # create and append
            # ->pass bundle, since want to access info.plist, etc
            results["items"].append(file.File(importer_bundle))

        return results
