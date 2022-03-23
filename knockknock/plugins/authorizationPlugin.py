__author__ = "patrick w"

"""
authorization plugin

    os x supports the notion of custom authorization plugins

    this plugin enumerates all such authorization plugins, that will be automatically loaded by the OS

"""

import glob
import logging
import os

# plugin framework import
from yapsy.IPlugin import IPlugin

# project imports
from knockknock import file, utils

LOGGER = logging.getLogger(__name__)

# directories where auth plugins live
AUTH_PLUGIN_DIRECTORIES = [
    "/System/Library/CoreServices/SecurityAgentPlugins/",
    "/Library/Security/SecurityAgentPlugins/",
]

# for output, item name
AUTH_PLUGIN_NAME = "Authorization Plugins"

# for output, description of items
AUTH_PLUGIN_DESCRIPTION = "Registered custom authorization plugins"

# plugin class
class scan(IPlugin):

    # init results dictionary
    # ->item name, description, and list
    def initResults(self, name, description):

        # results dictionary
        return {"name": name, "description": description, "items": []}

    # invoked by core
    def scan(self):

        # auth plugins
        authPlugins = []

        LOGGER.info("running scan")

        # init results dictionary
        results = self.initResults(AUTH_PLUGIN_NAME, AUTH_PLUGIN_DESCRIPTION)

        # get all files in auth plugin directories
        for authPluginDir in AUTH_PLUGIN_DIRECTORIES:
            LOGGER.info("scanning %s", authPluginDir)

            # get auth plugins
            authPlugins.extend(glob.glob(authPluginDir + "*"))

        # process
        # ->gets bundle's binary, then create file object and add to results
        for authPlugin in authPlugins:

            # skip any non-bundles
            # ->just do a directory check
            if not os.path.isdir(authPlugin):

                # skip
                continue

            # skip any invalid bundles
            if not utils.getBinaryFromBundle(authPlugin):

                # skip
                continue

            # create and append
            # ->pass bundle, since want to access info.plist, etc
            results["items"].append(file.File(authPlugin))

        return results
