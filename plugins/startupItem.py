__author__ = "patrick w"

"""
startup items

    startup items live in either /System/Library/StartupItems/ or /Library/StartupItems/

    to create a startup item,
        1) create a folder under one of these directories
        2) create a StartupParameters.plist file and script file that matches the name of the folder created in step 1

    this plugin examines files within the OS's startup items directories to find any startup items
"""

import glob
import os

# project imports
import file
import utils

# plugin framework import
from yapsy.IPlugin import IPlugin

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


class scan(IPlugin):

    # init results dictionary
    # ->plugin name, description, and list
    def initResults(self, name, description):

        # results dictionary
        return {"name": name, "description": description, "items": []}

    # invoked by core
    def scan(self):

        # dbg msg
        utils.logMessage(utils.MODE_INFO, "running scan")

        # init results dictionary
        results = self.initResults(STARTUP_ITEM_NAME, STARTUP_ITEM_DESCRIPTION)

        # iterate over all base startup item directories
        # ->look for startup items
        for startupItemBaseDirectory in STARTUP_ITEM_BASE_DIRECTORIES:

            # get sub directories
            # ->these are the actual startup items
            startupItemDirectories = glob.glob(startupItemBaseDirectory + "*")

            # check the sub directory (which is likely a startup item)
            # ->there should be a file (script) which matches the name of the sub-directory
            for startupItemDirectory in startupItemDirectories:

                # init the startup item
                startupItem = (
                    startupItemDirectory + "/" + os.path.split(startupItemDirectory)[1]
                )

                # check if it exists
                if os.path.exists(startupItem):

                    # save
                    results["items"].append(file.File(startupItem))

        return results
