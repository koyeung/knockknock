__author__ = "patrick w"

"""
	overrides provide a way for both sandboxed applications and launch daemons/agents to be automatically executed

	this plugin scans the OS's override directory and parses files to overridden items set for auto execution
"""

import os
import glob

# project imports
import file
import utils

# plugin framework import
from yapsy.IPlugin import IPlugin

# (base) directory that has overrides for launch* and apps
OVERRIDES_DIRECTORIES = [
    "/private/var/db/launchd.db/",
    "/private/var/db/com.apple.xpc.launchd",
]

# marker for finding sandboxed login item
MARKER = "/contents/library/loginitems/"

# directories for launch daemons and agents
LAUNCH_D_AND_A_DIRECTORIES = [
    "/System/Library/LaunchDaemons/",
    "/Library/LaunchDaemons/",
    "/System/Library/LaunchAgents/",
    "/Library/LaunchAgents/",
    "~/Library/LaunchAgents/",
]

# for output, item name
OVERRIDES_NAME = "Overrides"

# for output, description of items
OVERRIDES_DESCRIPTION = "Binaries that are executed before/during login"


class scan(IPlugin):

    # init results dictionary
    # ->plugin name, description, and list
    def initResults(self, name, description):

        # results dictionary
        return {"name": name, "description": description, "items": []}

    # invoked by core
    def scan(self):

        # overrides
        overrides = []

        # login items files
        overriddenItems = []

        # sandbox login items
        sandboxedLoginItems = None

        # dbg msg
        utils.logMessage(utils.MODE_INFO, "running scan")

        # init results dictionary
        results = self.initResults(OVERRIDES_NAME, OVERRIDES_DESCRIPTION)

        # get all overrides plists
        for overrideDirectory in OVERRIDES_DIRECTORIES:

            # get all
            overrides.extend(glob.glob(overrideDirectory + "*/overrides.plist"))

        # process
        # ->check all files for overrides
        for override in overrides:

            # wrap
            try:

                # load plist and check
                plistData = utils.loadPlist(override)

                # skip any plist files that couldn't be loaded
                if not plistData:

                    # skip
                    continue

                # extract sandboxed login items
                # ->helper apps
                if "_com.apple.SMLoginItemBookmarks" in plistData:

                    # extract all
                    # ->'_com.apple.SMLoginItemBookmarks' is key
                    sandboxedLoginItemsBookmarks = plistData[
                        "_com.apple.SMLoginItemBookmarks"
                    ]

                    # iterate over all
                    # ->extract from bookmark blob
                    for sandboxedLoginItem in sandboxedLoginItemsBookmarks:

                        # wrap
                        # ->here, allows just single item to be skipped
                        try:

                            # print 'sandboxed item from SMLoginItemBookmarks: %s' % sandboxedLoginItem

                            # print self.parseBookmark(sandboxedLoginItemsBookmarks[sandboxedLoginItem])

                            # ignore disabled ones
                            if not self.isOverrideEnabled(
                                plistData, sandboxedLoginItem
                            ):

                                # dbg msg
                                # print '%s is disabled!!' % sandboxedLoginItem

                                # skip
                                continue

                            # parse bookmark blob
                            # ->attempt to extract login item
                            loginItem = self.parseBookmark(
                                sandboxedLoginItemsBookmarks[sandboxedLoginItem]
                            )

                            # ignore files that don't exist
                            # ->some apps that don't cleanly uninstall leave entries here
                            if not os.path.exists(loginItem):

                                # skip
                                continue

                            # save extracted login item
                            if loginItem:

                                # save
                                results["items"].append(file.File(loginItem))

                        # ignore exceptions
                        # ->just try next time
                        except:

                            # skip
                            continue

                # now parse 'normal' overrides
                for overrideItem in plistData:

                    # wrap
                    # ->here, allows just single item to be skipped
                    try:

                        # skip the overrides that are also in the bookmark dictionary
                        # ->these were already processed (above)
                        if (
                            sandboxedLoginItemsBookmarks
                            and overrideItem in sandboxedLoginItemsBookmarks
                        ):

                            # skip
                            continue

                        # ignore disabled ones
                        if not self.isOverrideEnabled(plistData, overrideItem):

                            # skip
                            continue

                        # here, just got a bundle ID
                        # ->try to get the binary for it by searching launch daemon and agents
                        binaryForOveride = self.findBinaryForOveride(overrideItem)

                        # save binaries
                        if binaryForOveride:

                            # save
                            results["items"].append(file.File(binaryForOveride))

                    # ignore exceptions
                    # ->just try next time
                    except:

                        # skip
                        continue

            # ignore exceptions
            except Exception as e:

                # print e

                # skip
                continue

        return results

    # path to sandboxed login item (helper app) is in bookmark data
    # ->this is an undocumented blob of data that has the path to the login item somwhere in it
    #   to find it, code looks for string with '/contents/library/loginitems/' (as item has to be in there)
    def parseBookmark(self, bookmarkData):

        # extract login item
        loginItem = None

        # convert to str for search operations
        bookmarkDataStr = "".join(bookmarkData)

        # start of login item
        loginItemStart = -1

        # end of login item
        loginItemEnd = -1

        # wrap
        try:

            # scan thru binary data
            # look for marker ('/contents/library/loginitems/')
            markerOffset = bookmarkDataStr.find(MARKER)

            # try to find start/end
            if -1 != markerOffset:

                # scan backward to find ';'
                loginItemStart = bookmarkDataStr[:markerOffset].rfind(";")

                # scan foward to find NULL
                loginItemEnd = bookmarkDataStr[markerOffset:].find("\0")

            # extract logig item if start and end were found
            if -1 != loginItemStart and -1 != loginItemEnd:

                # extact item
                # note: skip ';' at front (thus the +1)
                loginItem = bookmarkDataStr[
                    loginItemStart + 1 : markerOffset + loginItemEnd
                ]

        # ignore exceptions
        except:

            # ignore
            pass

        return loginItem

    # determines in a override is enabled
    def isOverrideEnabled(self, plist, overrideKey):

        # enabled flag
        enabled = False

        # wrap
        try:

            # enable is the opposite of disabled
            enabled = not plist[overrideKey]["Disabled"]

        # ignore exception
        except:

            # ignore
            pass

        return enabled

    # given a bundle id (from an override entry) find the corresponding binary
    # ->assumes it will be a launch daemon or agent, and the bundle id is unique
    def findBinaryForOveride(self, bundleID):

        # the binary
        binary = None

        # wrap
        try:

            # expand launch daemons and agents directories
            directories = utils.expandPaths(LAUNCH_D_AND_A_DIRECTORIES)

            # attempt to find bundle ID in any of the directories
            for directory in directories:

                # init candidate plist path
                plistPath = directory + bundleID + ".plist"

                # check if there if candidate plist exists
                if not os.path.exists(plistPath):

                    # skip
                    continue

                # load plist
                plistData = utils.loadPlist(plistPath)

                # check if 'ProgramArguments' exists
                if "ProgramArguments" in plistData:

                    # extract program arguments
                    programArguments = plistData["ProgramArguments"]

                    # check if its a file
                    if os.path.isfile(programArguments[0]):

                        # happy, got binary for bundle id
                        binary = programArguments[0]

                        # bail
                        break

                # check if 'Program' key contains binary
                # ->e.g. /System/Library/LaunchAgents/com.apple.mrt.uiagent.plist
                elif "Program" in plistData:

                    # check if its a file
                    if os.path.isfile(plistData["Program"]):

                        # happy, got binary for bundle id
                        binary = plistData["Program"]

                        # bail
                        break

        # ignore exceptions
        except:

            # ignore
            pass

        return binary
