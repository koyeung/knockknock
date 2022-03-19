__author__ = "patrick w"

"""
	login and logout hooks allow a script or command to be executed during login/logout

    this plugin (which should be run as root) parses the login/logout plist file to extract any such hooks
"""

import os

# project imports
import file
import utils
import command

# plugin framwork import
from yapsy.IPlugin import IPlugin

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

# plugin class
class scan(IPlugin):

    # init results dictionary
    # ->item name, description, and list
    def initResults(self, name, description):

        # results dictionary
        return {"name": name, "description": description, "items": []}

    # invoked by core
    def scan(self):

        # results
        results = []

        # dbg
        utils.logMessage(utils.MODE_INFO, "running scan")

        # init results
        # ->for for login hook
        results.append(self.initResults(LOGIN_HOOK_NAME, LOGIN_HOOK_DESCRIPTION))

        # init results
        # ->for logout hook
        results.append(self.initResults(LOGOUT_HOOK_NAME, LOGOUT_HOOK_DESCRIPTION))

        # expand all login/out files
        logInOutFiles = utils.expandPaths(LOGIN_WINDOW_FILES)

        # scan each file
        for logInOutFile in logInOutFiles:

            # load plist
            plistData = utils.loadPlist(logInOutFile)

            # make sure plist loaded
            if plistData:

                # grab login hook
                if "LoginHook" in plistData:

                    # check if its a file
                    if os.path.isfile(plistData["LoginHook"]):

                        # save file
                        results[0]["items"].append(file.File(plistData["LoginHook"]))

                    # likely a command
                    # ->could be file that doesn't exist, but ok to still report
                    else:

                        # save command
                        results[0]["items"].append(
                            command.Command(plistData["LoginHook"], logInOutFile)
                        )

                # grab logout hook
                if "LogoutHook" in plistData:

                    # check if its a file
                    if os.path.isfile(plistData["LogoutHook"]):

                        # save file
                        results[1]["items"].append(file.File(plistData["LogoutHook"]))

                    # likely a command
                    # ->could be file that doesn't exist, but ok to still report
                    else:

                        # save command
                        results[1]["items"].append(
                            command.Command(plistData["LogoutHook"], logInOutFile)
                        )

        return results
