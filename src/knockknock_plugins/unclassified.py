"""
unclassified items

    the OS starts many processes automatically in ways that aren't easily classfied
    (e.g. from the kernel, or other OS processes start em, etc.)

    this plugin dumps the process list and attempts to list all binaries that are
    running, apparently automatically so..
"""
__author__ = "patrick w"

import logging

from knockknock import file, utils
from knockknock.plugin_base import KnockKnockPlugin

LOGGER = logging.getLogger(__name__)

# for output, item name
UNCLASSIFIED_NAME = "Unclassified Items"

# for output, description of items
UNCLASSIFIED_DESCRIPTION = "Items that are running, but could not be classified"


class Scan(KnockKnockPlugin):
    """Plugin class."""

    # invoked by core
    def scan(self):
        """Scan action."""
        # reported path
        reported_paths = []

        LOGGER.info("running scan")

        # init results
        results = self.init_results(UNCLASSIFIED_NAME, UNCLASSIFIED_DESCRIPTION)

        # get all running processes
        processes = utils.get_process_list()

        # set processes top parent
        # ->well, besides launchd (pid: 0x1)
        utils.set_first_parent(processes)

        # add process type (dock or not)
        utils.set_process_type(processes)

        # get all procs that don't have a dock icon
        # ->assume these aren't started by the user
        non_dock_procs = self.get_non_dock_procs(processes)

        # save all non-dock procs
        for process in non_dock_procs.values():

            # extract path
            path = process["path"]

            # ignore dups
            if path in reported_paths:

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
            reported_paths.append(path)

        return results

    @staticmethod
    def get_non_dock_procs(processes):
        """get all procs that don't have a dock icon.

        ->also make sure the parent isn't dockable
        """
        # dictionary of process that aren't dock icon capable
        non_dock_procs = {}

        # iterate over all processes
        # ->will check time
        for pid, process in processes.items():

            # skip those that don't have parents
            if process["gpid"] not in processes:
                # skip
                continue

            # grand parent
            parent = processes[process["gpid"]]

            # check if process (and parent!) isn't dockable
            if (
                utils.PROCESS_TYPE_BG == process["type"]
                and utils.PROCESS_TYPE_BG == parent["type"]
            ):

                # yups, save it
                non_dock_procs[pid] = process

        return non_dock_procs
