"""
rc script

    the /etc/rc.common, ect/rc.installer_cleanup, etc files contains commands that are
    executed at boot

    this plugin (very basically) parses this file, extacting all commands
    (not in functions)

"""
__author__ = "patrick w"

import logging
import os

# plugin framework import
from yapsy.IPlugin import IPlugin

# project imports
from knockknock import command, utils

LOGGER = logging.getLogger(__name__)

# various rc scripts
RC_SCRIPTS = ["rc.common", "rc.installer_cleanup", "rc.cleanup"]

# for output, item name
RC_SCRIPT_NAME = "RC Script"

# for output, description of items
RC_SCRIPT_DESCRIPTION = "Commands founds within the rc* files"


class Scan(IPlugin):
    """Plugin class."""

    @staticmethod
    def init_results(name, description):
        """Init results dictionary.

        ->item name, description, and list
        """
        # results dictionary
        return {"name": name, "description": description, "items": []}

    # invoked by core
    def scan(self):
        """Scan action."""
        LOGGER.info("running scan")

        # init results dictionary
        results = self.init_results(RC_SCRIPT_NAME, RC_SCRIPT_DESCRIPTION)

        # scan/parse all rc files
        for rc_script in RC_SCRIPTS:

            # get all commands in script file
            # ->note, commands in functions will be ignored...
            #   of course, if the function is invoked, this invocation will be displayed
            commands = utils.parse_bash_file(os.path.join("/etc", rc_script))

            # iterate over all commands
            # ->instantiate command obj and save into results
            for extracted_command in commands:

                # instantiate and save
                results["items"].append(command.Command(extracted_command, rc_script))

        return results
