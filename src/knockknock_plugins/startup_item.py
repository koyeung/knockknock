"""
startup items

    startup items live in either /System/Library/StartupItems/ or /Library/StartupItems/

    to create a startup item,
        1) create a folder under one of these directories
        2) create a StartupParameters.plist file and script file that matches the name of the folder
           created in step 1

    this plugin examines files within the OS's startup items directories to find any startup items
"""
__author__ = "patrick w"

import glob
import logging
import os

from knockknock import file
from knockknock.plugin_base import KnockKnockPlugin

LOGGER = logging.getLogger(__name__)

# base directories for startup items
STARTUP_ITEM_BASE_DIRECTORIES = [
    "/System/Library/StartupItems/",
    "/Library/StartupItems/",
    "/Library/Application Support/JAMF/ManagementFrameworkScripts/",
]

# for output, item name
STARTUP_ITEM_NAME = "Startup Items"

# for output, description of items
STARTUP_ITEM_DESCRIPTION = "Binaries that are..."


class Scan(KnockKnockPlugin):
    """Plugin class."""

    def scan(self):
        """Scan action."""
        LOGGER.info("running scan")

        # init results dictionary
        results = self.init_results(STARTUP_ITEM_NAME, STARTUP_ITEM_DESCRIPTION)

        # iterate over all base startup item directories
        # ->look for startup items
        for startup_item_base_directory in STARTUP_ITEM_BASE_DIRECTORIES:

            # get sub directories
            # ->these are the actual startup items
            startup_item_directories = glob.glob(startup_item_base_directory + "*")

            # check the sub directory (which is likely a startup item)
            # ->there should be a file (script) which matches the name of the sub-directory
            for startup_item_directory in startup_item_directories:

                # init the startup item
                startup_item = (
                    startup_item_directory
                    + "/"
                    + os.path.split(startup_item_directory)[1]
                )

                # check if it exists
                if os.path.exists(startup_item):

                    # save
                    results["items"].append(file.File(startup_item))

        return results
