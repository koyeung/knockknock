"""launchd.conf.

the /etc/launchd.conf file contains commands that are that are executed at boot by launchctl

this plugin (very basically) parses this file, extacting all such commands
And, Apple removed /etc/launchd.conf in 2014 or so.  This plugin ought to be disabled.
"""
__author__ = "patrick w"

import logging

from knockknock import command, utils
from knockknock.plugin_base import KnockKnockPlugin

LOGGER = logging.getLogger(__name__)

# path to launchd.conf
LAUNCHD_CONF_FILE = "/etc/launchd.conf"

# for output, item name
LAUNCHD_CONF_NAME = "Launchd Configuration File"

# for output, description of items
LAUNCHD_CONF_DESCRIPTION = "Commands that are executed by LaunchCtl"


class Scan(KnockKnockPlugin):
    """Plugin class."""

    def scan(self):
        """Scan action."""
        # commands
        commands = []

        LOGGER.info("running scan")

        # init results dictionary
        results = self.init_results(LAUNCHD_CONF_NAME, LAUNCHD_CONF_DESCRIPTION)

        # get all commands in launchd.conf
        # ->note, commands in functions will be ignored...
        commands = utils.parse_bash_file(LAUNCHD_CONF_FILE)

        # iterate over all commands
        # ->instantiate command obj and save into results
        for extracted_command in commands:

            # TODO: could prolly do some more advanced processing (e.g. look for bsexec, etc)

            # instantiate and save
            results["items"].append(command.Command(extracted_command))

        return results
