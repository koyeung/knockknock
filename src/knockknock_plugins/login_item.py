"""login items are the legit way to register applications for auto execution when a user logs in

this plugin parses the undocumented contents of all users' com.apple.loginitems.plist to find
login items
"""
__author__ = "patrick w"

import logging
import os

from knockknock import file, utils
from knockknock.plugin_base import KnockKnockPlugin

LOGGER = logging.getLogger(__name__)

# directory that has login items
# ->this is expanded for all user's on the system
LOGIN_ITEM_FILE = "~/Library/Preferences/com.apple.loginitems.plist"

# start of login item
LOGIN_ITEM_PREFIX = "file://"

# for output, item name
LOGIN_ITEM_NAME = "Login Items"

# for output, description of items
LOGIN_ITEM_DESCRIPTION = "Binaries that are executed at login"


class Scan(KnockKnockPlugin):
    """Plugin class."""

    def scan(self):
        """Scan action."""
        LOGGER.info("running scan")

        # init results dictionary
        results = self.init_results(LOGIN_ITEM_NAME, LOGIN_ITEM_DESCRIPTION)

        # process
        # ->open file and read each line
        for user_login_items in utils.expand_path(LOGIN_ITEM_FILE):

            LOGGER.info("scanning %s", user_login_items)

            # load plist and check
            plist_data = utils.load_plist(user_login_items)

            # extract sessions items
            sesssion_items = plist_data["SessionItems"]

            # extract custom list items
            custom_list_items = sesssion_items["CustomListItems"]

            # iterate over all login items
            for custom_list_item in custom_list_items:

                # extract alias data
                alias_data = list((custom_list_item["Alias"]).bytes())

                # parse alias data
                login_item = self.parse_alias_data(alias_data)

                # save extracted login item
                if login_item:
                    # save
                    results["items"].append(file.File(login_item))

        return results

    @staticmethod
    def parse_alias_data(alias_data):
        """Parse alias data.

        path to login item is in 'alias' data
        ->this is an undocumented blob of data that has the path to the login item somwhere in it
        to find it, code looks for data thats formatted size:str that's a file
        """
        # extract login item
        login_item = None

        # scan thru binary data
        # look for size:str that's a file
        for i, data in enumerate(alias_data):

            # extract size
            size = ord(data)

            # if what could be a size is reasonable
            # at least 2 (this could be higher) and smaller than rest of the data
            if size < 2 or size > len(alias_data) - i:
                # skip
                continue

            # extract possible file
            file_ = "/" + "".join(alias_data[i + 1 : i + 1 + size])

            # check if it exists
            if not os.path.exists(file_):
                # skip
                continue

            # found file
            login_item = file_

            # bail
            break

        return login_item
