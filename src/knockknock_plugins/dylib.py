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
import itertools
import logging
from collections import namedtuple
from pathlib import Path
from typing import Iterable, List, Optional

from knockknock import file, utils
from knockknock.plugin_base import KnockKnockPlugin

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

PListFile = namedtuple("PListFile", ["path", "plist"])


class Scan(KnockKnockPlugin):
    """Plugin class."""

    def scan(self):
        """Scan action."""
        LOGGER.info("running scan")

        # init results
        results = self.init_results(
            INSERTED_DYNAMIC_LIBRARIES_NAME, INSERTED_DYNAMIC_LIBRARIES_DESCRIPTION
        )

        # scan launch items for inserted dylibs
        launch_items = _scan_launch_items(LAUNCH_ITEMS_DIRECTORIES)
        if launch_items:
            results["items"].extend(launch_items)

        # scan all installed applications for inserted dylibs
        applications = _scan_applications()
        if applications:
            results["items"].extend(applications)

        return results


def _scan_launch_items(directories) -> Optional[List[file.File]]:
    """Scan launch agents or daemons.

    for each directory, load all plist's and look for 'DYLD_INSERT_LIBRARIES' key
    within a 'EnvironmentVariables'
    """
    # expand directories
    # ->ensures '~'s are expanded to all user's
    directories = utils.expand_paths(directories)

    launch_item_plist_paths: List[str] = []

    # get all files (plists) in launch daemon/agent directories
    for directory in directories:
        LOGGER.info("scanning %s", directory)

        # get launch daemon/agent plist
        assert directory.endswith("/"), "should be endswith '/'"
        launch_item_plist_paths.extend(glob.glob(directory + "*"))

    launch_item_plists = [
        PListFile(plist_path, utils.load_plist(plist_path))
        for plist_path in launch_item_plist_paths
    ]

    # check all plists for DYLD_INSERT_LIBRARIES
    # ->for each found, creates file object
    return _scan_plist_files(launch_item_plists, env_key=LAUNCH_ITEM_DYLD_KEY)


def _scan_applications() -> Optional[List[file.File]]:
    """Scan all installed applications.

    for each directory, load all apps' Info.plist and look for 'DYLD_INSERT_LIBRARIES' key
    within a 'LSEnvironment'
    """
    LOGGER.info("generating list of all installed apps (this may take some time)")

    installed_apps = utils.get_installed_apps()

    if not installed_apps:
        # in case system_profiler (to get installed apps) can timeout/throw exception, etc
        return None

    info_plists = []

    for app in installed_apps:

        app_name = app["_name"]

        if "path" not in app:
            LOGGER.warning(f"path not found in {app_name}")
            continue

        plist = utils.load_info_plist(app["path"])
        assert (
            "CFBundleInfoPlistURL" not in plist
        ), "ensure CFBundleInfoPlistURL not in plist and use Contents/Info.plist instead"

        plist_path_obj = Path(f"{app['path']}") / "Contents" / "Info.plist"
        if plist_path_obj.exists():
            plist_path = str(plist_path_obj)
        else:
            LOGGER.warning(f"{plist_path_obj} not exists; skip {app_name}")
            continue

        info_plists.append(PListFile(plist_path, plist))

    # check all plists for DYLD_INSERT_LIBRARIES
    # ->for each found, creates file object
    return _scan_plist_files(info_plists, env_key=APPLICATION_DYLD_KEY)


def _scan_plist_files(
    plist_files: Iterable[PListFile], /, *, env_key: str
) -> List[file.File]:
    """Scan a list of plist.

    -> create file obj if interested *DYLD_INSERT_LIBRARIES found
    """
    return list(
        itertools.chain.from_iterable(
            _scan_plist_file(plist_file, env_key=env_key) for plist_file in plist_files
        )
    )


def _scan_plist_file(plist_file: PListFile, /, *, env_key: str) -> List[file.File]:

    results: List[file.File] = []

    # check for env key
    # -> will be either 'EnvironmentVariables' or 'LSEnvironment'
    # depends on if launch item or app
    if env_key in plist_file.plist:

        env_plist = plist_file.plist[env_key]

        # check for/save DYLD_INSERT_LIBRARIES
        if "DYLD_INSERT_LIBRARIES" in env_plist:
            # create file obj and append to results
            results.append(
                file.File(env_plist["DYLD_INSERT_LIBRARIES"], plist_file.path)
            )

        # check for/save __XPC_DYLD_INSERT_LIBRARIES
        if "__XPC_DYLD_INSERT_LIBRARIES" in env_plist:
            # create file obj and append to results
            results.append(
                file.File(env_plist["__XPC_DYLD_INSERT_LIBRARIES"], plist_file.path)
            )

    return results
