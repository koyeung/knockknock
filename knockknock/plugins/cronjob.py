__author__ = "patrick w"

"""
cronjobs

    conjobs allow scripts or commands to be executed on time-based intervals

    this plugin reads all users' cronjob files (/private/var/at/tabs/*) to extract all registered cronjobs
"""

import glob
import logging

# plugin framework import
from yapsy.IPlugin import IPlugin

# project imports
from knockknock import command, utils

LOGGER = logging.getLogger(__name__)

# directory that has cron jobs
CRON_JOB_DIRECTORY = "/private/var/at/tabs/"

# for output, item name
CRON_JOBS_NAME = "Cron Jobs"

# for output, description of items
CRON_JOBS_DESCRIPTION = "Jobs that are scheduled to run on specifed basis"

# plugin class
class scan(IPlugin):

    # init results dictionary
    # ->item name, description, and list
    def initResults(self, name, description):

        # results dictionary
        return {"name": name, "description": description, "items": []}

    # invoked by core
    def scan(self):

        # cron jobs files
        cronJobFiles = []

        # init results dictionary
        results = self.initResults(CRON_JOBS_NAME, CRON_JOBS_DESCRIPTION)

        LOGGER.info("running scan")

        # get all files in kext directories
        cronJobFiles.extend(glob.glob(CRON_JOB_DIRECTORY + "*"))

        # process
        # ->open file and read each line
        for cronJobFile in cronJobFiles:

            # open file
            # ->read each line (for now, assume 1 cron job per line)
            with open(cronJobFile, "r") as file:

                # read each line
                for cronJobData in file:

                    # skip comment lines
                    if cronJobData.lstrip().startswith("#"):

                        # skip
                        continue

                    # create and append job
                    results["items"].append(command.Command(cronJobData.strip()))

        return results
