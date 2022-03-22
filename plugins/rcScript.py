__author__ = "patrick w"

"""
rc script

    the /etc/rc.common, ect/rc.installer_cleanup, etc files contains commands that are executed at boot

    this plugin (very basically) parses this file, extacting all commands (not in functions)

"""

import glob
import os

# plugin framework import
from yapsy.IPlugin import IPlugin

# project imports
from knockknock import command, utils

# various rc scripts
RC_SCRIPTS = ["rc.common", "rc.installer_cleanup", "rc.cleanup"]

# for output, item name
RC_SCRIPT_NAME = "RC Script"

# for output, description of items
RC_SCRIPT_DESCRIPTION = "Commands founds within the rc* files"

# plugin class
class scan(IPlugin):

    # init results dictionary
    # ->plugin name, description, and list
    def initResults(self, name, description):

        # results dictionary
        return {"name": name, "description": description, "items": []}

    # invoked by core
    def scan(self):

        # commands
        commands = []

        # dbg msg
        utils.logMessage(utils.MODE_INFO, "running scan")

        # init results dictionary
        results = self.initResults(RC_SCRIPT_NAME, RC_SCRIPT_DESCRIPTION)

        # scan/parse all rc files
        for rcScript in RC_SCRIPTS:

            # get all commands in script file
            # ->note, commands in functions will be ignored...
            #   of course, if the function is invoked, this invocation will be displayed
            commands = utils.parseBashFile(os.path.join("/etc", rcScript))

            # iterate over all commands
            # ->instantiate command obj and save into results
            for extractedCommand in commands:

                # instantiate and save
                results["items"].append(command.Command(extractedCommand, rcScript))

        return results
