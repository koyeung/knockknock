__author__ = "patrick w"

"""
	login items are the legit way to register applications for auto execution when a user logs in

	this plugin parses the undocumented contents of all users' com.apple.loginitems.plist to find login items
"""

import logging
import os

# plugin framework import
from yapsy.IPlugin import IPlugin

# project imports
from knockknock import file, utils

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

# plugin class
class scan(IPlugin):

    # init results dictionary
    # ->plugin name, description, and list
    def initResults(self, name, description):

        # results dictionary
        return {"name": name, "description": description, "items": []}

    # invoked by core
    def scan(self):

        # login items files
        loginItems = []

        LOGGER.info("running scan")

        # init results dictionary
        results = self.initResults(LOGIN_ITEM_NAME, LOGIN_ITEM_DESCRIPTION)

        # process
        # ->open file and read each line
        for userLoginItems in utils.expandPath(LOGIN_ITEM_FILE):

            # wrap
            try:

                LOGGER.info("scanning %s", userLoginItems)

                # load plist and check
                plistData = utils.loadPlist(userLoginItems)

                # extract sessions items
                sesssionItems = plistData["SessionItems"]

                # extract custom list items
                customListItems = sesssionItems["CustomListItems"]

                # iterate over all login items
                for customListItem in customListItems:

                    # wrap it
                    try:

                        # extact alias data
                        aliasData = list((customListItem["Alias"]).bytes())

                        # parse alias data
                        loginItem = self.parseAliasData(aliasData)

                        # save extracted login item
                        if loginItem:

                            # save
                            results["items"].append(file.File(loginItem))

                    # ignore exceptions
                    except Exception as e:

                        # skip
                        continue

            # ignore exceptions
            except:

                # skip
                continue

        return results

    # path to login item is in 'alias' data
    # ->this is an undocumented blob of data that has the path to the login item somwhere in it
    #   to find it, code looks for data thats formatted size:str that's a file
    def parseAliasData(self, aliasData):

        # extract login item
        loginItem = None

        # scan thru binary data
        # look for size:str that's a file
        for i in range(0, len(aliasData)):

            # extract size
            size = ord(aliasData[i])

            # if what could be a size is reasonable
            # at least 2 (this could be higher) and smaller than rest of the data
            if size < 2 or size > len(aliasData) - i:
                # skip
                continue

            # extract possible file
            file = "/" + "".join(aliasData[i + 1 : i + 1 + size])

            # wrap
            try:

                # check if it exists
                if not os.path.exists(file):

                    # skip
                    continue

            # ignore exceptions
            except:

                # skip
                continue

            # found file
            loginItem = file

            # bail
            break

        return loginItem
