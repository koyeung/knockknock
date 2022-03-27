"""launch daemons and agents.

launch daemons and agents are binaries that can be automatically loaded by the OS
(similar to Windows services)

this plugin parses all plists within the OS's and users' launchd daemon/agent directories
and extracts all auto-launched daemons/agents
"""
__author__ = "patrick w"

import glob
import logging
import os

from knockknock import file, utils
from knockknock.plugin_base import KnockKnockPlugin

LOGGER = logging.getLogger(__name__)

# directories for launch daemons
LAUNCH_DAEMON_DIRECTORIES = [
    "/System/Library/LaunchDaemons/",
    "/Library/LaunchDaemons/",
]

# directories for launch agents
LAUNCH_AGENTS_DIRECTORIES = [
    "/System/Library/LaunchAgents/",
    "/Library/LaunchAgents/",
    "~/Library/LaunchAgents/",
]

# for output, item name
LAUNCH_DAEMON_NAME = "Launch Daemons"

# for output, description of items
LAUNCH_DAEMON_DESCRIPTION = "Non-interactive daemons that are executed by Launchd"

# for output, item name
LAUNCH_AGENT_NAME = "Launch Agents"

# for output, description of items
LAUNCH_AGENT_DESCRIPTION = "Interactive agents that are executed by Launchd"

# (base) directory that has overrides for launch* and apps
OVERRIDES_DIRECTORY = "/private/var/db/launchd.db/"


# TODO: malware could abuse 'WatchPaths' 'StartOnMount' 'StartInterval', etc....
#     for now, we just look for the basics ('RunAtLoad' and 'KeepAlive')


class Scan(KnockKnockPlugin):
    """Plugin class."""

    # overrides items
    overridden_items = {}

    def scan(self):
        """Scan action."""
        # results
        results = []

        LOGGER.info("running scan")

        # init results
        # ->for launch daemons
        results.append(self.init_results(LAUNCH_DAEMON_NAME, LAUNCH_DAEMON_DESCRIPTION))

        # init results
        # ->for launch agents
        results.append(self.init_results(LAUNCH_AGENT_NAME, LAUNCH_AGENT_DESCRIPTION))

        # init overriden items
        # ->scans overrides plists, and populates 'overriddenItems' class variable
        self.get_overridden_items()

        # scan for auto-run launch daemons
        # ->save in first index of array
        results[0]["items"] = self.scan_launch_items(LAUNCH_DAEMON_DIRECTORIES)

        # scan for auto-run launch agents
        # ->save in second index of array
        results[1]["items"] = self.scan_launch_items(LAUNCH_AGENTS_DIRECTORIES)

        return results

    def scan_launch_items(self, directories):
        """Scan either launch agents or daemons.

        ->arg is list of directories to scan
        """
        # launch items
        launch_items = []

        # results
        results = []

        # expand directories
        # ->ensures '~'s are expanded to all user's
        directories = utils.expand_paths(directories)

        # get all files (plists) in launch daemon/agent directories
        for directory in directories:

            LOGGER.info("scanning %s", directory)

            # get launch daemon/agent
            launch_items.extend(glob.glob(directory + "*"))

        # process
        # ->get all auto-run launch services
        auto_run_items = self.auto_run_binaries(launch_items)

        # iterate over all auto-run items (list of the plist and the binary)
        # ->create file object and add to results
        for auto_run_item in auto_run_items:

            # create and append
            results.append(file.File(auto_run_item[0], auto_run_item[1]))

        return results

    def auto_run_binaries(self, plists):
        """Get auto run binaries.

        given a list of (launch daemon/agent) plists
        ->return a list of their binaries that are set to auto run
        this is done by looking for 'RunAtLoad' &&/|| 'KeepAlive' set to true
        """
        # auto run binaries
        auto_run_bins = []

        # iterate over all plist
        # ->check 'RunAtLoad' (for true) and then extract the first item in the 'ProgramArguments'
        for plist in plists:

            # wrap
            try:

                # program args from plist
                program_arguments = []

                # load plist
                plist_data = utils.load_plist(plist)

                # skip files that couldn't be loaded
                if not plist_data:

                    # skip
                    continue

                # skip non-autorun'd items
                if not self.is_auto_run(plist_data):

                    # skip
                    continue

                # check for 'ProgramArguments' key
                if "ProgramArguments" in plist_data:

                    # extract program arguments
                    program_arguments = plist_data["ProgramArguments"]

                    # skip funky args
                    if len(program_arguments) < 1:

                        # skip
                        continue

                    # extract launch item's binary
                    # ->should be first item in args array
                    binary = program_arguments[0]

                    # skip files that aren't found
                    # ->will try 'which' to resolve things like 'bash', etc
                    if not os.path.isfile(binary):

                        # try which
                        binary = utils.which(binary)
                        if not binary:

                            # skip
                            continue

                # also check for 'Program' key
                # ->e.g. /System/Library/LaunchAgents/com.apple.mrt.uiagent.plist
                elif "Program" in plist_data:

                    # extract binary
                    binary = plist_data["Program"]

                    # skip files that aren't found
                    # ->will try 'which' to resolve things like 'bash', etc
                    if not os.path.isfile(binary):

                        # try which
                        binary = utils.which(binary)
                        if not binary:

                            # skip
                            continue

                # save extracted launch daemon/agent binary
                if binary:

                    # save
                    auto_run_bins.append([binary, plist])

            # ignore exceptions
            except Exception:  # pylint: disable=broad-except
                LOGGER.exception(f"{plist=}")

        return auto_run_bins

    def is_auto_run(self, plist_data):
        """Determine if a launch item is set to auto run.

        ->kinda some tricky(ish) logic based on a variety of conditions/flags
        """
        # flag
        is_auto_run = False

        #'run at load' flag
        run_at_load = -1

        #'keep alive' flag
        keep_alive = -1

        #'on demand' flag
        on_demand = -1

        # skip disabled launch items (overrides)
        # ->note: overriddenItems var is a dictionary that has the disabled status
        if (
            "Label" in plist_data
            and plist_data["Label"] in self.overridden_items
            and self.overridden_items[plist_data["Label"]]
        ):

            # print 'skipping disabled item (override): %s'
            # % self.overriddenItems[plistData['Label']]

            # nope
            return False

        # skip disabled launch items
        # ->have to also check the overrides dictionary though
        if "Disabled" in plist_data and plist_data["Disabled"]:

            # make sure its not overridden (and enabled there)
            if (
                not plist_data["Label"] in self.overridden_items
                or not self.overridden_items[plist_data["Label"]]
            ):

                # skip
                # print 'skipping disabled item: %s' % self.overriddenItems[plistData['Label']]

                # nope
                return False

        # set 'run at load' flag
        if "RunAtLoad" in plist_data and bool is type(plist_data["RunAtLoad"]):

            # set
            run_at_load = plist_data["RunAtLoad"]

        # set 'keep alive' flag
        if "KeepAlive" in plist_data and bool is type(plist_data["KeepAlive"]):

            # set
            keep_alive = plist_data["KeepAlive"]

        # set 'on demand' flag
        if "OnDemand" in plist_data:

            # set
            on_demand = plist_data["OnDemand"]

        # first check 'run at load' & 'keep alive'
        # ->either of these set to ok, means auto run!
        if run_at_load is True or keep_alive is True:

            # yups
            is_auto_run = True

        # when neither 'RunAtLoad' and 'KeepAlive' not found
        # ->check if 'OnDemand' is set to false (e.g. HackingTeam)
        elif ((run_at_load == -1) and (keep_alive == -1)) and (on_demand is False):

            # yups
            is_auto_run = True

        return is_auto_run

    def get_overridden_items(self):
        """Scan the overrides files to determine if launch item is enabled/disabled."""
        # get all overrides plists
        overrides = glob.glob(OVERRIDES_DIRECTORY + "*/overrides.plist")

        # process
        # ->check all files for overrides
        for overide in overrides:

            # wrap
            try:

                LOGGER.info("opening %s", overide)

                # load plist and check
                plist_data = utils.load_plist(overide)
                if not plist_data:

                    # skip
                    continue

                # now parse 'normal' overrides
                for override_item in plist_data:

                    # check if item has disabled flag (true/false)
                    if "Disabled" in plist_data[override_item]:

                        # save
                        self.overridden_items[override_item] = plist_data[
                            override_item
                        ]["Disabled"]

            # ignore exceptions
            except Exception:  # pylint: disable=broad-except
                LOGGER.exception(f"{overide=}")
