"""cronjobs.

conjobs allow scripts or commands to be executed on time-based intervals
this plugin reads all users' cronjob files (/private/var/at/tabs/*)
to extract all registered cronjobs
"""
__author__ = "patrick w"

import glob
import logging

from knockknock import command
from knockknock.plugin_base import KnockKnockPlugin

LOGGER = logging.getLogger(__name__)

# directory that has cron jobs
CRON_JOB_DIRECTORY = "/private/var/at/tabs/"

# for output, item name
CRON_JOBS_NAME = "Cron Jobs"

# for output, description of items
CRON_JOBS_DESCRIPTION = "Jobs that are scheduled to run on specifed basis"


class Scan(KnockKnockPlugin):
    """Plugin class."""

    def scan(self):
        """Scan action."""
        # cron jobs files
        cron_job_files = []

        # init results dictionary
        results = self.init_results(CRON_JOBS_NAME, CRON_JOBS_DESCRIPTION)

        LOGGER.info("running scan")

        # get all files in kext directories
        cron_job_files.extend(glob.glob(CRON_JOB_DIRECTORY + "*"))

        # process
        # ->open file and read each line
        for cron_job_file in cron_job_files:

            # open file
            # ->read each line (for now, assume 1 cron job per line)
            with open(cron_job_file, "r", encoding="utf-8") as file:

                # read each line
                for cron_job_data in file:

                    # skip comment lines
                    if cron_job_data.lstrip().startswith("#"):

                        # skip
                        continue

                    # create and append job
                    results["items"].append(command.Command(cron_job_data.strip()))

        return results
