#!/usr/bin/python
#
# KnockKnock by Patrick Wardle is licensed under a Creative Commons Attribution-NonCommercial 4.0 International License.
#

import logging
import os
import sys
from pathlib import Path

from yapsy.PluginManager import PluginManager

# project imports
from . import file, output, utils, virusTotal, whitelist

# directory containing plugins
PLUGIN_DIR = "plugins/"

# args
args = None

LOGGER = logging.getLogger(__name__)


# main interface
def knocknock():

    logging.basicConfig(level=logging.WARNING)

    # results
    results = []

    try:

        # init
        # ->logging, plugin manager, etc
        plugin_manager = _init_knockknock()
        LOGGER.info("initialization complete")

        # list plugins and bail
        if args.list:

            # display plugins
            _list_plugins(plugin_manager)

            # bail
            return True

        # scan for thingz
        results = _scan(plugin_name=args.plugin, plugin_manager=plugin_manager)

        # make sure scan succeeded
        if None == results:

            LOGGER.error("scan failed")
            return False

        # depending on args
        # filter out apple signed binaries, or whitelisted binaries, etc
        if not args.apple or not args.whitelist:  # or args.signed:

            # iterate over all results
            # ->one for each startup item type
            for result in results:

                # ignored/whitelisted items
                ignoredItems = []

                # scan each startup object
                # ->if it should be ingored, add to ignore list
                for startupObj in result["items"]:

                    # filter out files
                    # ->depending on args, singed by apple, whitelisted, etc
                    if isinstance(startupObj, file.File):

                        # by default, ignore signed by Apple
                        if not args.apple and startupObj.signedByApple:

                            # add to list
                            ignoredItems.append(startupObj)

                    # ignore white listed items
                    if not args.whitelist and startupObj.isWhitelisted:

                        # add to list
                        ignoredItems.append(startupObj)

                    # now that we are done iterating
                    # ->subtract out all ignored/whitelisted items
                    result["items"] = list(set(result["items"]) - set(ignoredItems))

        # filter out dups in unclassified plugin
        # ->needed since it just looks at the proc list
        removeUnclassDups(results)

        # get vt results
        if not args.disableVT:

            LOGGER.info("querying VirusTotal - sit tight!")

            # process
            # ->will query VT and add VT info to all files
            virusTotal.processResults(results)

        # format output
        # ->normal output or JSON
        formattedResults = output.formatResults(results, args.json)

        # show em
        print(formattedResults.encode("utf-8", "xmlcharrefreplace").decode())

    # top level exception handler
    except Exception as e:

        LOGGER.exception("failed")
        return False

    return True


# filter out dups in unclassified plugin
# ->needed, since it just looks at the proc list so grabs items that are likely detected/classified elsewhere
def removeUnclassDups(results):

    # unique unclass'd items
    uniqueItems = []

    # get unclassifed results
    unclassItems = [
        result for result in results if result["name"] == "Unclassified Items"
    ]

    # bail if there aren't any
    if not unclassItems:

        # none
        return

    # just want the dictionary
    # ->first item
    unclassItems = unclassItems[0]

    # get all hashes
    hashes = allHashes(results)

    # look at each unclass item
    # ->remove it if its reported elsewhere
    for unclassItem in unclassItems["items"]:

        # only keep otherwise unknown items
        if 0x1 == hashes.count(unclassItem.hash):

            # save
            uniqueItems.append(unclassItem)

    # update
    unclassItems["items"] = uniqueItems

    return


# return a list of hashes of all startup items (files)
def allHashes(results):

    # list of hashes
    hashes = []

    # iterate over all results
    # ->grab file hashes
    for result in results:

        # hash all files
        for startupObj in result["items"]:

            # check for file
            if isinstance(startupObj, file.File):

                # save hash
                hashes.append(startupObj.hash)

    return hashes


# initialize knockknock
def _init_knockknock() -> PluginManager:

    # global args
    global args

    # global import
    global argparse

    # get python version
    python_version = sys.version_info

    if (python_version.major, python_version.minor) < (3, 8):
        LOGGER.error("KnockKnock requires python 3.8+ (found: %s)", python_version)
        return False

    # try import argparse
    # ->should work now since just checked that python is 2.7+
    try:

        # import
        import argparse

    # handle exception
    # ->bail w/ error msg
    except ImportError as exc:
        LOGGER.error("could not load required module (argparse)")
        raise

    # parse options/args
    # ->will bail (with msg) if usage is incorrect
    args = parseArgs()

    if args.verbosity:
        logging.getLogger().setLevel(logging.DEBUG)

    LOGGER.info("initialized logging")

    # check version (Mavericks/Yosemite for now)
    # ->this isn't a fatal error for now, so just log a warning for unsupported versions
    if not utils.isSupportedOS():
        LOGGER.warning(
            "%s is not an officially supported OS X version (your mileage may vary)",
            ".".join(utils.getOSVersion()),
        )
    else:
        LOGGER.info("%s is a supported OS X version", ".".join(utils.getOSVersion()))

    # load python <-> Objc bindings
    # ->might fail if non-Apple version of python is being used
    assert (
        utils.loadObjcBindings()
    ), "python <-> Objc bindings/module not installed\n       run via /usr/bin/python or install modules via 'pip install pyobjc' to fix"

    # load whitelists
    whitelist.loadWhitelists()

    plugin_manager = _get_plugin_manager()
    LOGGER.info("initialized plugin manager")

    # giving warning about r00t
    if 0 != os.geteuid():
        LOGGER.info("not running as r00t...some results may be missed (e.g. CronJobs)")

    return plugin_manager


# parse args
def parseArgs():

    # init parser
    parser = argparse.ArgumentParser()

    # arg, plugin name
    # ->optional
    parser.add_argument("-p", "--plugin", help="name of plugin")

    # arg, verbose
    # ->optional
    parser.add_argument(
        "-v", "--verbosity", help="enable verbose output", action="store_true"
    )

    # arg, display binaries signed by Apple
    # ->optional
    parser.add_argument(
        "-a", "--apple", help="include Apple-signed binaries", action="store_true"
    )

    # arg, display binaries that are whitelisted
    # ->optional
    parser.add_argument(
        "-w", "--whitelist", help="include white-listed binaries", action="store_true"
    )

    # arg, hide binaries that are signed (by anybody)
    # ->optional
    # parser.add_argument('-s', '--signed', help='exclude all signed binaries', action='store_true')

    # arg, list plugins
    # ->optional
    parser.add_argument("-l", "--list", help="list all plugins", action="store_true")

    # arg, output JSON
    # ->optional
    parser.add_argument(
        "-j", "--json", help="produce output in JSON format", action="store_true"
    )

    # arg, disable VT integration
    # ->optional
    parser.add_argument(
        "-d", "--disableVT", help="disable VirusTotal integration", action="store_true"
    )

    # parse args
    return parser.parse_args()


# init plugin manager
def _get_plugin_manager() -> PluginManager:

    plugin_manager = PluginManager()
    assert plugin_manager, "failed to create plugin manager"

    # set plugin path
    plugin_manager.setPluginPlaces([Path(utils.getKKDirectory()).parent / PLUGIN_DIR])

    # get all plugins
    plugin_manager.collectPlugins()

    return plugin_manager


# list plugins
def _list_plugins(plugin_manager) -> None:

    LOGGER.info("listing plugins")

    # interate over all plugins
    for plugin in sorted(plugin_manager.getAllPlugins(), key=lambda x: x.name):

        # dbg msg
        # ->always use print, since -v might not have been used
        print("%s -> %s" % (os.path.split(plugin.path)[1], plugin.name))


# scanz!
def _scan(*, plugin_name, plugin_manager):

    # results
    results = []

    # flag indicating plugin was found
    # ->only relevant when a plugin name is specified
    foundPlugin = False

    # full scan?
    if not plugin_name:
        LOGGER.info("beginning full scan")

    # plugin only
    else:
        LOGGER.info("beginning scan using %s plugin", plugin_name)

    # interate over all plugins
    for plugin in plugin_manager.getAllPlugins():

        # results from plugin
        pluginResults = None

        # no plugin names means run 'em all
        if not plugin_name:
            LOGGER.info("executing plugin: %s", plugin.name)

            # execute current plugin
            pluginResults = plugin.plugin_object.scan()

        # try to find match
        else:

            # get name of plugin file as name
            # ->e.g. /plugins/somePlugin.py -> 'somePlugin'
            currentPlugin = os.path.split(plugin.path)[1]

            # check for match
            if plugin_name.lower() == currentPlugin.lower():

                # found it
                foundPlugin = True

                LOGGER.info("executing requested plugin: %s", plugin_name)

                # execute plugin
                pluginResults = plugin.plugin_object.scan()

        # save plugin output
        if pluginResults:

            # plugins normally return a single dictionary of results
            if isinstance(pluginResults, dict):

                # save results
                results.append(pluginResults)

            # some plugins though can return a list of dictionaries
            # ->e.g. the launch daemon/agent plugin (one dictionary for each type)
            elif isinstance(pluginResults, list):

                # save results
                results.extend(pluginResults)

        # check if specific plugin was specified and found
        # ->if so, can bail
        if plugin_name and foundPlugin:

            # bail
            break

    # sanity check
    # -> make sure if a specific plugin was specified, it was found/exec'd
    if plugin_name and not foundPlugin:

        LOGGER.error("did not find requested plugin")

        # reset results
        results = None

    return results


# invoke main interface
if __name__ == "__main__":

    # main interface
    knocknock()
