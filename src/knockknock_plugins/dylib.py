"""dylibs (loaded via DYLD_INSERT_LIBRARIES).

the DYLD_INSERT_LIBRARIES environment variable can be set to the path of a dynamic library (.dylib)

for local settings, the plugin scans plists of launch daemons and agents,
and all installed apps to determine if any dylibs are set for global settings, the plugin...
"""
__author__ = "patrick w"


# for launch agents
# edit com.blah.blah.plist
# <key>EnvironmentVariables</key>
#   <dict>
#   <key>DYLD_INSERT_LIBRARIES</key>
#   <string>/path/to/dylib</string>
#  </dict>
#
# for apps
# <key>LSEnvironment</key>
#   <dict>
# 	  <key>DYLD_INSERT_LIBRARIES</key>
# 	  <string>/path/to/dylib</string>
# 	  </dict>
# /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework
# /Support/lsregister -v -f /Applications/ApplicationName.app

import glob
import logging

# plugin framework import
from yapsy.IPlugin import IPlugin

# project imports
from knockknock import file, utils

LOGGER = logging.getLogger(__name__)

# directories for launch daemons and agents
LAUNCH_ITEMS_DIRECTORIES = [
    "/System/Library/LaunchDaemons/",
    "/Library/LaunchDaemons/",
    "/System/Library/LaunchAgents/",
    "/Library/LaunchAgents/",
    "~/Library/LaunchAgents/",
]

# key for launch items
LAUNCH_ITEM_DYLD_KEY = "EnvironmentVariables"

# key for applications
APPLICATION_DYLD_KEY = "LSEnvironment"

# for output, item name
INSERTED_DYNAMIC_LIBRARIES_NAME = "(inserted) Dynamic Libraries"

# for output, description of items
INSERTED_DYNAMIC_LIBRARIES_DESCRIPTION = (
    "Dynamic Libraries that are set to be injected via DYLD_INSERT_LIBRARIES"
)


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
        # results
        results = []

        LOGGER.info("running scan")

        # init results
        results = self.init_results(
            INSERTED_DYNAMIC_LIBRARIES_NAME, INSERTED_DYNAMIC_LIBRARIES_DESCRIPTION
        )

        # scan launch items for inserted dylibs
        launch_items = _scan_launch_items(LAUNCH_ITEMS_DIRECTORIES)
        if launch_items:

            # save
            results["items"].extend(launch_items)

        # scan all installed applications for inserted dylibs
        applications = _scan_applications()
        if applications:

            # save
            results["items"].extend(applications)

        return results


def _scan_launch_items(directories):
    """Scan launch agents or daemons.

    for each directory, load all plist's and look for 'DYLD_INSERT_LIBRARIES' key
    within a 'EnvironmentVariables'
    """
    # launch items
    launch_items = []

    # expand directories
    # ->ensures '~'s are expanded to all user's
    directories = utils.expand_paths(directories)

    # get all files (plists) in launch daemon/agent directories
    for directory in directories:

        LOGGER.info("scanning %s", directory)

        # get launch daemon/agent plist
        launch_items.extend(glob.glob(directory + "*"))

    # check all plists for DYLD_INSERT_LIBRARIES
    # ->for each found, creates file object
    return _scan_plists(launch_items, LAUNCH_ITEM_DYLD_KEY)


def _scan_applications():
    """Scan all installed applications.

    for each directory, load all apps' Info.plist and look for 'DYLD_INSERT_LIBRARIES' key
    within a 'LSEnvironment'
    """
    # app plists
    app_plists = []

    LOGGER.info("generating list of all installed apps (this may take some time)")

    # get all installed apps
    installed_apps = utils.get_installed_apps()

    # sanity check
    # ->using system_profiler (to get installed apps) can timeout/throw exception, etc
    if not installed_apps:

        # bail
        return None

    # now, get Info.plist for each app
    for app in installed_apps:

        # skip apps that don't have a path
        if not "path" in app:

            # skip
            continue

        # get/load app's Info.plist
        plist = utils.load_info_plist(app["path"])

        # skip apps that don't have Info.plist
        if not plist:

            # skip
            continue

        # save plist for processing
        app_plists.append(plist)

    # check all plists for DYLD_INSERT_LIBRARIES
    # ->for each found, creates file object
    return _scan_plists(app_plists, APPLICATION_DYLD_KEY, is_loaded=True)


def _scan_plists(plists, key, is_loaded=False):
    """Scan a list of plist.

    ->check for 'DYLD_INSERT_LIBRARIES' in plist, and if found, create file obj/result
    """
    # results
    results = []

    # sanity check
    if not plists:

        # bail
        return None

    # iterate over all plist
    # ->check for 'DYLD_INSERT_LIBRARIES' enviroment variable
    for plist in plists:

        # wrap
        try:

            # load contents of plist if needed
            if not is_loaded:

                # save path
                plist_path = plist

                # load it and check
                loaded_plist = utils.load_plist(plist)
                if not loaded_plist:

                    # skip
                    continue

            # otherwise it's already loaded
            # ->use as is
            else:

                # set
                loaded_plist = plist

                # get path
                plist_path = utils.get_path_from_plist(loaded_plist)

            # check for env key
            # -> will be either 'EnvironmentVariables' or 'LSEnvironment'
            # depending if launch item or app
            if key in loaded_plist:

                # check for/save DYLD_INSERT_LIBRARIES
                if "DYLD_INSERT_LIBRARIES" in loaded_plist[key]:

                    # create file obj and append to results
                    results.append(
                        file.File(
                            loaded_plist[key]["DYLD_INSERT_LIBRARIES"], plist_path
                        )
                    )

                # check for/save __XPC_DYLD_INSERT_LIBRARIES
                if "__XPC_DYLD_INSERT_LIBRARIES" in loaded_plist[key]:

                    # create file obj and append to results
                    results.append(
                        file.File(
                            loaded_plist[key]["__XPC_DYLD_INSERT_LIBRARIES"], plist_path
                        )
                    )

        # ignore exceptions
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception(f"{plist=}")

    return results
