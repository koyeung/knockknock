"""overrides provide a way for both sandboxed applications and launch daemons/agents
to be automatically executed

this plugin scans the OS's override directory and parses files to overridden items set for
auto execution
"""
__author__ = "patrick w"


import glob
import logging
import os

# plugin framework import
from yapsy.IPlugin import IPlugin

# project imports
from knockknock import file, utils

LOGGER = logging.getLogger(__name__)

# (base) directory that has overrides for launch* and apps
OVERRIDES_DIRECTORIES = [
    "/private/var/db/launchd.db/",
    "/private/var/db/com.apple.xpc.launchd",
]

# marker for finding sandboxed login item
MARKER = "/contents/library/loginitems/"

# directories for launch daemons and agents
LAUNCH_D_AND_A_DIRECTORIES = [
    "/System/Library/LaunchDaemons/",
    "/Library/LaunchDaemons/",
    "/System/Library/LaunchAgents/",
    "/Library/LaunchAgents/",
    "~/Library/LaunchAgents/",
]

# for output, item name
OVERRIDES_NAME = "Overrides"

# for output, description of items
OVERRIDES_DESCRIPTION = "Binaries that are executed before/during login"


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
        # pylint: disable=too-many-branches
        # overrides
        overrides = []

        LOGGER.info("running scan")

        # init results dictionary
        results = self.init_results(OVERRIDES_NAME, OVERRIDES_DESCRIPTION)

        # get all overrides plists
        for override_directory in OVERRIDES_DIRECTORIES:

            # get all
            overrides.extend(glob.glob(override_directory + "*/overrides.plist"))

        # process
        # ->check all files for overrides
        for override in overrides:  # pylint: disable=too-many-nested-blocks

            # wrap
            try:

                # load plist and check
                plist_data = utils.load_plist(override)

                # skip any plist files that couldn't be loaded
                if not plist_data:

                    # skip
                    continue

                sandboxed_login_items_bookmarks = None

                # extract sandboxed login items
                # ->helper apps
                if "_com.apple.SMLoginItemBookmarks" in plist_data:

                    # sandbox login items
                    #
                    # extract all
                    # ->'_com.apple.SMLoginItemBookmarks' is key
                    sandboxed_login_items_bookmarks = plist_data[
                        "_com.apple.SMLoginItemBookmarks"
                    ]

                    # iterate over all
                    # ->extract from bookmark blob
                    for sandboxed_login_item in sandboxed_login_items_bookmarks:

                        # wrap
                        # ->here, allows just single item to be skipped
                        try:

                            # print 'sandboxed item from SMLoginItemBookmarks: %s'
                            # % sandboxedLoginItem

                            # print self.parseBookmark(
                            # sandboxedLoginItemsBookmarks[sandboxedLoginItem])

                            # ignore disabled ones
                            if not self.is_override_enabled(
                                plist_data, sandboxed_login_item
                            ):

                                # dbg msg
                                # print '%s is disabled!!' % sandboxedLoginItem

                                # skip
                                continue

                            # parse bookmark blob
                            # ->attempt to extract login item
                            login_item = self.parse_bookmark(
                                sandboxed_login_items_bookmarks[sandboxed_login_item]
                            )

                            # ignore files that don't exist
                            # ->some apps that don't cleanly uninstall leave entries here
                            if not os.path.exists(login_item):

                                # skip
                                continue

                            # save extracted login item
                            if login_item:

                                # save
                                results["items"].append(file.File(login_item))

                        # ignore exceptions
                        # ->just try next time
                        except Exception:  # pylint: disable=broad-except
                            LOGGER.exception(f"{sandboxed_login_item=}")
                            # skip
                            continue

                # now parse 'normal' overrides
                for override_item in plist_data:

                    # wrap
                    # ->here, allows just single item to be skipped
                    try:

                        # skip the overrides that are also in the bookmark dictionary
                        # ->these were already processed (above)
                        if (
                            sandboxed_login_items_bookmarks
                            and override_item in sandboxed_login_items_bookmarks
                        ):

                            # skip
                            continue

                        # ignore disabled ones
                        if not self.is_override_enabled(plist_data, override_item):

                            # skip
                            continue

                        # here, just got a bundle ID
                        # ->try to get the binary for it by searching launch daemon and agents
                        binary_for_overide = self.find_binary_for_overide(override_item)

                        # save binaries
                        if binary_for_overide:

                            # save
                            results["items"].append(file.File(binary_for_overide))

                    # ignore exceptions
                    # ->just try next time
                    except Exception:  # pylint: disable=broad-except
                        LOGGER.exception(f"{override_item=}")

            # ignore exceptions
            except Exception:  # pylint: disable=broad-except
                LOGGER.exception(f"{override=}")

        return results

    @staticmethod
    def parse_bookmark(bookmark_data):
        """Parse bookmark.

        # path to sandboxed login item (helper app) is in bookmark data
        # ->this is an undocumented blob of data that has the path to the login item somwhere in it
        #   to find it, code looks for string with '/contents/library/loginitems/'
        # (as item has to be in there)
        """
        # extract login item
        login_item = None

        # convert to str for search operations
        bookmark_data_str = "".join(bookmark_data)

        # start of login item
        login_item_start = -1

        # end of login item
        login_item_end = -1

        # wrap
        try:

            # scan thru binary data
            # look for marker ('/contents/library/loginitems/')
            marker_offset = bookmark_data_str.find(MARKER)

            # try to find start/end
            if -1 != marker_offset:

                # scan backward to find ';'
                login_item_start = bookmark_data_str[:marker_offset].rfind(";")

                # scan foward to find NULL
                login_item_end = bookmark_data_str[marker_offset:].find("\0")

            # extract logig item if start and end were found
            if -1 != login_item_start and -1 != login_item_end:

                # extact item
                # note: skip ';' at front (thus the +1)
                login_item = bookmark_data_str[
                    login_item_start + 1 : marker_offset + login_item_end
                ]

        # ignore exceptions
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception(f"{bookmark_data=}")

        return login_item

    @staticmethod
    def is_override_enabled(plist, override_key):
        """Determines in a override is enabled."""
        # enabled flag
        enabled = False

        # wrap
        try:

            # enable is the opposite of disabled
            enabled = not plist[override_key]["Disabled"]

        # ignore exception
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception(f"{plist=} {override_key=}")

        return enabled

    @staticmethod
    def find_binary_for_overide(bundle_id):
        """Find binary for override.

        # given a bundle id (from an override entry) find the corresponding binary
        # ->assumes it will be a launch daemon or agent, and the bundle id is unique
        """
        # the binary
        binary = None

        # wrap
        try:

            # expand launch daemons and agents directories
            directories = utils.expand_paths(LAUNCH_D_AND_A_DIRECTORIES)

            # attempt to find bundle ID in any of the directories
            for directory in directories:

                # init candidate plist path
                plist_path = directory + bundle_id + ".plist"

                # check if there if candidate plist exists
                if not os.path.exists(plist_path):

                    # skip
                    continue

                # load plist
                plist_data = utils.load_plist(plist_path)

                # check if 'ProgramArguments' exists
                if "ProgramArguments" in plist_data:

                    # extract program arguments
                    program_arguments = plist_data["ProgramArguments"]

                    # check if its a file
                    if os.path.isfile(program_arguments[0]):

                        # happy, got binary for bundle id
                        binary = program_arguments[0]

                        # bail
                        break

                # check if 'Program' key contains binary
                # ->e.g. /System/Library/LaunchAgents/com.apple.mrt.uiagent.plist
                elif "Program" in plist_data:

                    # check if its a file
                    if os.path.isfile(plist_data["Program"]):

                        # happy, got binary for bundle id
                        binary = plist_data["Program"]

                        # bail
                        break

        # ignore exceptions
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception(f"{bundle_id=}")

        return binary
