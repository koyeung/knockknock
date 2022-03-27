"""browser extensions.

browser extensions can provide a way for code to be executed whenever the browser is launched
this plugin parses meta data files/directories of Safari, Chrome,
and Firefox to find all installed extensions
"""
__author__ = "patrick w"

import glob
import json
import logging
import os

# names are lazily loaded in pyobjc modules
# pylint: disable=no-member
import CoreServices

from knockknock import extension, utils
from knockknock.plugin_base import KnockKnockPlugin

LOGGER = logging.getLogger(__name__)

# safari's extensions path
SAFARI_EXTENSION_DIRECTORY = "~/Library/Safari/Extensions/Extensions.plist"

# for output, item name
SAFARI_EXTENSIONS_NAME = "Safari Browser Extensions"

# for output, description of items
SAFARI_EXTENSIONS_DESCRIPTION = "Code that is hosted and executed by Apple Safari"

# google chrome's paths to pref files
# ->contains info about installed extensions
CHROME_DIRECTORIES = ["~/Library/Application Support/Google/Chrome/Default/Preferences"]

# for output, item name
CHROME_EXTENSIONS_NAME = "Chrome Browser Extensions"

# for output, description of items
CHROME_EXTENSIONS_DESCRIPTION = "Code that is hosted and executed by Google Chrome"

# firefox's profile directory
# ->contains each profile's addons
FIREFOX_PROFILE_DIRECTORY = "~/Library/Application Support/Firefox/Profiles"

# for output, item name
FIREFOX_EXTENSIONS_NAME = "Firefox Browser Extensions"

# for output, description of items
FIREFOX_EXTENSIONS_DESCRIPTION = "Code that is hosted and executed by Firefox"


class Scan(KnockKnockPlugin):
    """Plugin class."""

    def scan(self):
        """Scan action."""
        # results
        results = []

        LOGGER.info("running scan")

        # get list of installed browsers
        browsers = self.get_installed_browsers()

        # iterate over all browsers
        # ->scan each
        for browser in browsers:

            # scan Safari extensions
            if "Safari.app" in browser:

                LOGGER.info("safari installed, scanning for extensions")

                # init results
                results.append(
                    self.init_results(
                        SAFARI_EXTENSIONS_NAME, SAFARI_EXTENSIONS_DESCRIPTION
                    )
                )

                # scan
                results[len(results) - 1]["items"] = self.scan_extensions_safari()

            # scan Chrome extensions
            if "Google Chrome.app" in browser:

                LOGGER.info("chrome installed, scanning for extensions")

                # init results
                results.append(
                    self.init_results(
                        CHROME_EXTENSIONS_NAME, CHROME_EXTENSIONS_DESCRIPTION
                    )
                )

                # scan
                results[len(results) - 1]["items"] = self.scan_extensions_chrome()

            # scan Firefox extensions
            if "Firefox.app" in browser:

                LOGGER.info("firefox installed, scanning for extensions")

                # init results
                results.append(
                    self.init_results(
                        FIREFOX_EXTENSIONS_NAME, FIREFOX_EXTENSIONS_DESCRIPTION
                    )
                )

                # scan
                results[len(results) - 1]["items"] = self.scan_extensions_firefox()

        return results

    @staticmethod
    def get_installed_browsers():
        """Get list of installed browsers."""
        # wrap
        try:

            # list of installed browsers
            installed_browsers = []

            # get list of app IDs that can handle 'https'
            # ->i.e. browsers
            browsers_ids = CoreServices.LSCopyAllHandlersForURLScheme("https")

            # app IDs to full paths to the apps
            for browser_id in browsers_ids:

                # wrap
                try:

                    # use LSFindApplicationForInfo to convert ID to app path
                    # returns a list, 3rd item an NSURL to the browser
                    browser_url = CoreServices.LSFindApplicationForInfo(
                        CoreServices.kLSUnknownCreator, browser_id, None, None, None
                    )[2]

                    # convert the url to a filepath
                    installed_browsers.append(browser_url.path())

                # ignore exceptions
                # ->just want to try next browser
                except Exception:  # pylint: disable=broad-except
                    LOGGER.exception(f"get_installed_browsers {browser_id=}")

        # ignore exceptions
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception("get_installed_browsers")

        return installed_browsers

    @staticmethod
    def scan_extensions_safari():
        """Scan for Safari extension.

        ->load plist file, and parse looking for 'Installed Extensions'
        """
        # results
        results = []

        # get list of all chrome's preferences file
        # ->these contain JSON w/ info about all extensions
        safari_extension_files = utils.expand_path(SAFARI_EXTENSION_DIRECTORY)

        # parse each for extensions
        for safari_extension_file in safari_extension_files:

            # wrap
            try:

                # load extension file
                plist_data = utils.load_plist(safari_extension_file)

                # ensure data looks ok
                if not plist_data or "Installed Extensions" not in plist_data:

                    # skip/try next
                    continue

                # the list of extensions are stored in the 'settings' key
                extensions = plist_data["Installed Extensions"]

                # scan all extensions
                # ->skip ones that are disabled, white listed, etc
                for current_extension in extensions:

                    # dictionary for extension info
                    extension_info = {}

                    # skip disabled plugins
                    if (
                        "Enabled" in current_extension
                        and not current_extension["Enabled"]
                    ):

                        # skip
                        continue

                    # extract path
                    if "Archive File Name" in current_extension:

                        # name
                        extension_info["path"] = (
                            safari_extension_file
                            + "/"
                            + current_extension["Archive File Name"]
                        )

                    # extract name
                    if "Bundle Directory Name" in current_extension:

                        # path
                        extension_info["name"] = current_extension[
                            "Bundle Directory Name"
                        ]

                    # create and append
                    results.append(extension.Extension(extension_info))

            # ignore exceptions
            except Exception:  # pylint: disable=broad-except
                LOGGER.exception(f"{safari_extension_file=}")

        return results

    @staticmethod
    def scan_extensions_chrome():
        """Scan for Chrome extensions.

        ->load JSON file, and parse looking for installed/enabled extensions
        """
        # results
        results = []

        # get list of all chrome's preferences file
        # ->these contain JSON w/ info about all extensions
        chrome_preferences = utils.expand_paths(CHROME_DIRECTORIES)

        # parse each for extensions
        for chrome_preference_file in chrome_preferences:

            # wrap
            try:

                # open preference file and load it
                with open(chrome_preference_file, "r", encoding="utf-8") as file:

                    # load as JSON
                    preferences = json.loads(file.read())
                    if not preferences:

                        # skip/try next
                        continue

                # pref file just has the list of ids,
                # everything else we might want is in
                # os.path.dirname(chromePreferenceFile)
                # + '/Extensions/' + id + version + manifest.json
                # manifest has name, description

                extensions = preferences["extensions"]["install_signature"]["ids"]

                # scan all extensions
                # ->skip ones that are disabled, white listed, etc
                for extension_key in extensions:

                    # dictionary for extension info
                    extension_info = {}

                    # save key
                    extension_info["id"] = extension_key
                    extension_path = (
                        os.path.dirname(chrome_preference_file)
                        + "/Extensions/"
                        + extension_info["id"]
                    )

                    extdir = os.listdir(extension_path)
                    for verdir in extdir:
                        manpath = extension_path + "/" + verdir + "/manifest.json"

                        with open(manpath, "r", encoding="utf-8") as file:
                            manifest = json.loads(file.read())
                            if not manifest:
                                continue

                        extension_info["path"] = manpath
                        extension_info["name"] = manifest["name"]
                        extension_info["description"] = manifest["description"]

                        # create and append
                        results.append(extension.Extension(extension_info))

            # ignore exceptions
            except Exception:  # pylint: disable=broad-except
                LOGGER.exception(f"{chrome_preference_file=}")

        return results

    @staticmethod
    def scan_extensions_firefox():
        """Scan for firefox extensions.

        ->open/parse all 'addons.json' and 'extension.json' files
        """  # pylint: disable=too-many-branches
        # results
        results = []

        # dictionary of extension IDs
        # ->needed since they can show up in both addons.json and extensions.json
        extension_ids = []

        # get list of all firefox's profile directories
        # ->these contain profiles, that in turn, contain a files ('addons.json/extensions.json')
        # about the extensions
        firefox_profile_directories = utils.expand_path(FIREFOX_PROFILE_DIRECTORY)

        # iterate over all addons and extensions files in profile directories
        # ->extact all addons and extensions
        for firefox_profile_directory in firefox_profile_directories:

            # get list of all 'addon.json' files
            firefox_extension_files = glob.glob(
                firefox_profile_directory + "/*.default*/addons.json"
            )

            # and also all 'extensions.json' files
            firefox_extension_files.extend(
                glob.glob(firefox_profile_directory + "/*.default*/extensions.json")
            )

            # open/parse each addon file
            # ->contains list of addons (extensions)
            for firefox_extension_file in firefox_extension_files:

                # wrap
                try:

                    # open extension file and load it
                    with open(firefox_extension_file, "r", encoding="utf-8") as file:

                        # load as JSON
                        addons = json.loads(file.read())["addons"]
                        if not addons:

                            # skip/try next
                            continue

                # ignore exceptions
                except Exception:  # pylint: disable=broad-except
                    LOGGER.exception(f"{firefox_extension_file=}")

                    # skip/try next
                    continue

                # extract all addons/extensions
                # ->in both addons and extensions json files, called addons :/
                for addon in addons:

                    # dictionary for addon/extension info
                    extension_info = {}

                    # wrap
                    try:

                        # extract id
                        if "id" in addon:

                            # save
                            extension_info["id"] = addon["id"]

                        # skip duplicates
                        # ->extensions can show up in addons.json and extensions.json
                        if addon["id"] in extension_ids:

                            # skip dupe
                            continue

                        # json in addons.json file is formatted one way
                        if "addons.json" == os.path.split(firefox_extension_file)[1]:

                            # extract name
                            if "name" in addon:

                                # save
                                extension_info["name"] = addon["name"]

                            # extract description
                            if "description" in addon:

                                # save
                                extension_info["description"] = addon[
                                    "description"
                                ].replace("\n", " ")

                            # build path
                            # ->should be in the extensions/ folder, under <id>.XPI
                            path = (
                                os.path.split(firefox_extension_file)[0]
                                + "/extensions/"
                                + addon["id"]
                                + ".xpi"
                            )

                            # ignore .xpi's that don't exist
                            if not os.path.exists(path):

                                # skip
                                continue

                            # save path
                            extension_info["path"] = path

                        # json in extensions.json file is formatted another way
                        else:

                            # extract name
                            if (
                                "defaultLocale" in addon
                                and "name" in addon["defaultLocale"]
                            ):

                                # save
                                extension_info["name"] = addon["defaultLocale"]["name"]

                            # extract description
                            if (
                                "defaultLocale" in addon
                                and "description" in addon["defaultLocale"]
                            ):

                                # save
                                extension_info["description"] = addon["defaultLocale"][
                                    "description"
                                ]

                            # build path
                            # ->should be a directory in the extensions/ folder, under <id>
                            path = (
                                os.path.split(firefox_extension_file)[0]
                                + "/extensions/"
                                + addon["id"]
                            )

                            # ignore those that don't exist
                            if not os.path.exists(path):

                                # skip
                                continue

                            # save path
                            extension_info["path"] = path

                        # save extension id
                        # ->used to prevent dupes
                        extension_ids.append(extension_info["id"])

                        # create and append addon (extension)
                        results.append(extension.Extension(extension_info))

                    # ignore exceptions
                    except Exception:  # pylint: disable=broad-except
                        LOGGER.exception(f"{addon=}")

        return results
