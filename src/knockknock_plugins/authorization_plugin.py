"""authorization plugin.

os x supports the notion of custom authorization plugins
this plugin enumerates all such authorization plugins, that will be automatically loaded by the OS
"""
__author__ = "patrick w"


import glob
import logging
import os

# plugin framework import
from yapsy.IPlugin import IPlugin

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


class Scan(IPlugin):
    """Plugin class."""

    @staticmethod
    def init_results(name, description):
        """Init results dictionary.

        ->item name, description, and list
        """
        # results dictionary
        return {"name": name, "description": description, "items": []}

    def scan(self):
        """Scan action."""
        # auth plugins
        auth_plugins = []

        LOGGER.info("running scan")

        # init results dictionary
        results = self.init_results(AUTH_PLUGIN_NAME, AUTH_PLUGIN_DESCRIPTION)

        # get all files in auth plugin directories
        for auth_plugin_dir in AUTH_PLUGIN_DIRECTORIES:
            LOGGER.info("scanning %s", auth_plugin_dir)

            # get auth plugins
            auth_plugins.extend(glob.glob(auth_plugin_dir + "*"))

        # process
        # ->gets bundle's binary, then create file object and add to results
        for auth_plugin in auth_plugins:

            # skip any non-bundles
            # ->just do a directory check
            if not os.path.isdir(auth_plugin):

                # skip
                continue

            # skip any invalid bundles
            if not utils.get_binary_from_bundle(auth_plugin):

                # skip
                continue

            # create and append
            # ->pass bundle, since want to access info.plist, etc
            results["items"].append(file.File(auth_plugin))

        return results
