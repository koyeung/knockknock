__author__ = "patrick w"

"""
unclassified items

    the OS starts many processes automatically in ways that aren't easily classfied
    (e.g. from the kernel, or other OS processes start em, etc.)

    this plugin dumps the process list and attempts to list all binaries that are running, apparently automatically so..
"""

import glob
import os

# project imports
import file
import utils

# plugin framework import
from yapsy.IPlugin import IPlugin

# for output, item name
UNCLASSIFIED_NAME = "Unclassified Items"

# for output, description of items
UNCLASSIFIED_DESCRIPTION = "Items that are running, but could not be classified"


class scan(IPlugin):

    # init results dictionary
    # ->item name, description, and list
    def initResults(self, name, description):

        # results dictionary
        return {"name": name, "description": description, "items": []}

    # invoked by core
    def scan(self):

        # reported path
        reportedPaths = []

        # dbg msg
        utils.logMessage(utils.MODE_INFO, "running scan")

        # init results
        results = self.initResults(UNCLASSIFIED_NAME, UNCLASSIFIED_DESCRIPTION)

        # get all running processes
        processes = utils.getProcessList()

        # set processes top parent
        # ->well, besides launchd (pid: 0x1)
        utils.setFirstParent(processes)

        # add process type (dock or not)
        utils.setProcessType(processes)

        # get all procs that don't have a dock icon
        # ->assume these aren't started by the user
        nonDockProcs = self.getNonDockProcs(processes)

        # save all non-dock procs
        for pid in nonDockProcs:

            # extract path
            path = nonDockProcs[pid]["path"]

            # ignore dups
            if path in reportedPaths:

                # skip
                continue

            # ignore things in /opt/X11/
            # ->owned by r00t, so this should be ok....
            if path.startswith("/opt/X11/"):

                # skip
                continue

            # save
            results["items"].append(file.File(path))

            # record
            reportedPaths.append(path)

        return results

    # get all procs that don't have a dock icon
    # ->also make sure the parent isn't dockable
    def getNonDockProcs(self, processes):

        # dictionary of process that aren't dock icon capable
        nonDockProcs = {}

        # iterate over all processes
        # ->will check time
        for pid in processes:

            # get current process
            process = processes[pid]

            # skip those that don't have parents
            if process["gpid"] not in processes:

                # skip
                continue

            # grand parent
            parent = processes[process["gpid"]]

            # check if process (and parent!) isn't dockable
            if (
                utils.PROCESS_TYPE_BG == process["type"]
                and utils.PROCESS_TYPE_BG == process["type"]
            ):

                # yups, save it
                nonDockProcs[pid] = process

        return nonDockProcs
