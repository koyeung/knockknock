__author__ = "patrick w"

"""
launch daemons and agents

    launch daemons and agents are binaries that can be automatically loaded by the OS (similar to Windows services)

    this plugin parses all plists within the OS's and users' launchd daemon/agent directories and extracts
    all auto-launched daemons/agents
"""

import glob
import logging
import os

# plugin framework import
from yapsy.IPlugin import IPlugin

# project imports
from knockknock import file, utils

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


class scan(IPlugin):

    # overrides items
    overriddenItems = {}

    # init results dictionary
    # ->item name, description, and list
    def initResults(self, name, description):

        # results dictionary
        return {"name": name, "description": description, "items": []}

    # invoked by core
    def scan(self):

        # results
        results = []

        LOGGER.info("running scan")

        # init results
        # ->for launch daemons
        results.append(self.initResults(LAUNCH_DAEMON_NAME, LAUNCH_DAEMON_DESCRIPTION))

        # init results
        # ->for launch agents
        results.append(self.initResults(LAUNCH_AGENT_NAME, LAUNCH_AGENT_DESCRIPTION))

        # init overriden items
        # ->scans overrides plists, and populates 'overriddenItems' class variable
        self.getOverriddenItems()

        # scan for auto-run launch daemons
        # ->save in first index of array
        results[0]["items"] = self.scanLaunchItems(LAUNCH_DAEMON_DIRECTORIES)

        # scan for auto-run launch agents
        # ->save in second index of array
        results[1]["items"] = self.scanLaunchItems(LAUNCH_AGENTS_DIRECTORIES)

        return results

    # scan either launch agents or daemons
    # ->arg is list of directories to scan
    def scanLaunchItems(self, directories):

        # launch items
        launchItems = []

        # results
        results = []

        # expand directories
        # ->ensures '~'s are expanded to all user's
        directories = utils.expandPaths(directories)

        # get all files (plists) in launch daemon/agent directories
        for directory in directories:

            LOGGER.info("scanning %s", directory)

            # get launch daemon/agent
            launchItems.extend(glob.glob(directory + "*"))

        # process
        # ->get all auto-run launch services
        autoRunItems = self.autoRunBinaries(launchItems)

        # iterate over all auto-run items (list of the plist and the binary)
        # ->create file object and add to results
        for autoRunItem in autoRunItems:

            # create and append
            results.append(file.File(autoRunItem[0], autoRunItem[1]))

        return results

    # given a list of (launch daemon/agent) plists
    # ->return a list of their binaries that are set to auto run
    #   this is done by looking for 'RunAtLoad' &&/|| 'KeepAlive' set to true
    def autoRunBinaries(self, plists):

        # auto run binaries
        autoRunBins = []

        # iterate over all plist
        # ->check 'RunAtLoad' (for true) and then extract the first item in the 'ProgramArguments'
        for plist in plists:

            # wrap
            try:

                # program args from plist
                programArguments = []

                # load plist
                plistData = utils.loadPlist(plist)

                # skip files that couldn't be loaded
                if not plistData:

                    # skip
                    continue

                # skip non-autorun'd items
                if not self.isAutoRun(plistData):

                    # skip
                    continue

                # check for 'ProgramArguments' key
                if "ProgramArguments" in plistData:

                    # extract program arguments
                    programArguments = plistData["ProgramArguments"]

                    # skip funky args
                    if len(programArguments) < 1:

                        # skip
                        continue

                    # extract launch item's binary
                    # ->should be first item in args array
                    binary = programArguments[0]

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
                elif "Program" in plistData:

                    # extract binary
                    binary = plistData["Program"]

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
                    autoRunBins.append([binary, plist])

            # ignore exceptions
            except Exception as e:

                # ignore
                pass

        return autoRunBins

    # determine if a launch item is set to auto run
    # ->kinda some tricky(ish) logic based on a variety of conditions/flags
    def isAutoRun(self, plistData):

        # flag
        isAutoRun = False

        #'run at load' flag
        runAtLoad = -1

        #'keep alive' flag
        keepAlive = -1

        #'on demand' flag
        onDemand = -1

        # skip disabled launch items (overrides)
        # ->note: overriddenItems var is a dictionary that has the disabled status
        if (
            "Label" in plistData
            and plistData["Label"] in self.overriddenItems
            and self.overriddenItems[plistData["Label"]]
        ):

            # print 'skipping disabled item (override): %s' % self.overriddenItems[plistData['Label']]

            # nope
            return False

        # skip disabled launch items
        # ->have to also check the overrides dictionary though
        if "Disabled" in plistData and plistData["Disabled"]:

            # make sure its not overridden (and enabled there)
            if (
                not plistData["Label"] in self.overriddenItems
                or not self.overriddenItems[plistData["Label"]]
            ):

                # skip
                # print 'skipping disabled item: %s' % self.overriddenItems[plistData['Label']]

                # nope
                return False

        # set 'run at load' flag
        if "RunAtLoad" in plistData and bool is type(plistData["RunAtLoad"]):

            # set
            runAtLoad = plistData["RunAtLoad"]

        # set 'keep alive' flag
        if "KeepAlive" in plistData and bool is type(plistData["KeepAlive"]):

            # set
            keepAlive = plistData["KeepAlive"]

        # set 'on demand' flag
        if "OnDemand" in plistData:

            # set
            onDemand = plistData["OnDemand"]

        # first check 'run at load' & 'keep alive'
        # ->either of these set to ok, means auto run!
        if True == runAtLoad or True == keepAlive:

            # yups
            isAutoRun = True

        # when neither 'RunAtLoad' and 'KeepAlive' not found
        # ->check if 'OnDemand' is set to false (e.g. HackingTeam)
        elif ((-1 == runAtLoad) and (-1 == keepAlive)) and (False == onDemand):

            # yups
            isAutoRun = True

        return isAutoRun

    # scan the overrides files to determine if launch item is enabled/disabled
    def getOverriddenItems(self):

        # get all overrides plists
        overrides = glob.glob(OVERRIDES_DIRECTORY + "*/overrides.plist")

        # process
        # ->check all files for overrides
        for overide in overrides:

            # wrap
            try:

                LOGGER.info("opening %s", overide)

                # load plist and check
                plistData = utils.loadPlist(overide)
                if not plistData:

                    # skip
                    continue

                # now parse 'normal' overrides
                for overrideItem in plistData:

                    # check if item has disabled flag (true/false)
                    if "Disabled" in plistData[overrideItem]:

                        # save
                        self.overriddenItems[overrideItem] = plistData[overrideItem][
                            "Disabled"
                        ]

            # ignore exceptions
            except Exception as e:

                # skip
                continue

        return
