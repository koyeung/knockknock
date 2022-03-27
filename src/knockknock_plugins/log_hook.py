"""login and logout hooks allow a script or command to be executed during login/logout.

this plugin (which should be run as root) parses the login/logout plist file to extract any such
hooks
"""
__author__ = "patrick w"

import logging
import os
from pathlib import Path

from knockknock import command, file, utils
from knockknock.plugin_base import KnockKnockPlugin

LOGGER = logging.getLogger(__name__)

# login window directories
LOGIN_WINDOW_FILES = [
    "/private/var/root/Library/Preferences/com.apple.loginwindow.plist",
    "/Library/Preferences/com.apple.loginwindow.plist",
    "~/Library/Preferences/com.apple.loginwindow.plist",
]

# for output, item name
LOGIN_HOOK_NAME = "Login Hook"

# for output, description of items
LOGIN_HOOK_DESCRIPTION = "Command that is executed at login"

# for output, item name
LOGOUT_HOOK_NAME = "Logout Hook"

# for output, description of items
LOGOUT_HOOK_DESCRIPTION = "Command that is executed at logout"


class Scan(KnockKnockPlugin):
    """Plugin class."""

    def scan(self):
        """Scan action."""
        # results
        results = []

        LOGGER.info("running scan")

        # init results
        # ->for for login hook
        results.append(self.init_results(LOGIN_HOOK_NAME, LOGIN_HOOK_DESCRIPTION))

        # init results
        # ->for logout hook
        results.append(self.init_results(LOGOUT_HOOK_NAME, LOGOUT_HOOK_DESCRIPTION))

        # expand all login/out files
        log_in_out_files = utils.expand_paths(Path(file_) for file_ in LOGIN_WINDOW_FILES)

        # scan each file
        for log_in_out_file in log_in_out_files:

            # load plist
            plist_data = utils.load_plist(log_in_out_file)

            # make sure plist loaded
            if plist_data:

                # grab login hook
                if "LoginHook" in plist_data:

                    # check if its a file
                    if os.path.isfile(plist_data["LoginHook"]):

                        # save file
                        results[0]["items"].append(file.File(plist_data["LoginHook"]))

                    # likely a command
                    # ->could be file that doesn't exist, but ok to still report
                    else:

                        # save command
                        results[0]["items"].append(
                            command.Command(plist_data["LoginHook"], log_in_out_file)
                        )

                # grab logout hook
                if "LogoutHook" in plist_data:

                    # check if its a file
                    if os.path.isfile(plist_data["LogoutHook"]):

                        # save file
                        results[1]["items"].append(file.File(plist_data["LogoutHook"]))

                    # likely a command
                    # ->could be file that doesn't exist, but ok to still report
                    else:

                        # save command
                        results[1]["items"].append(
                            command.Command(plist_data["LogoutHook"], log_in_out_file)
                        )

        return results
