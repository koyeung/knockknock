#!/usr/bin/python
#
# KnockKnock by Patrick Wardle is licensed under
# a Creative Commons Attribution-NonCommercial 4.0 International License.
#

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

from yapsy.PluginManager import PluginManager

from . import file, output, plugin_base, utils, virustotal

LOGGER = logging.getLogger(__name__)

#: minimum supported macOS version
_MIN_OS_VERSION = (12, 0)

#: minimum expected python version
_MIN_PYTHON_VERSION = (3, 8)

#: Categories of knockknock plugins
_KK_PLUGINS_CATEGORY = "knockknock"


def knocknock():
    """Entry point."""

    logging.basicConfig(level=logging.WARNING)

    # parse options/args
    # ->will bail (with msg) if usage is incorrect
    args = _parse_args()

    _init_knockknock(args)

    plugin_manager = _get_plugin_manager()
    LOGGER.info("initialized plugin manager")

    LOGGER.info("initialization complete")

    # list plugins and bail
    if args.list:
        _list_plugins(plugin_manager)
        return

    # scan for thingz
    results = _scan(plugin_name=args.plugin, plugin_manager=plugin_manager)

    # make sure scan succeeded
    assert results, "scan failed"

    # depending on args
    # filter out apple signed binaries, or whitelisted binaries, etc
    if not args.apple or not args.whitelist:  # or args.signed:

        # iterate over all results
        # ->one for each startup item type
        for result in results:

            # ignored/whitelisted items
            ignored_items = []

            # scan each startup object
            # ->if it should be ingored, add to ignore list
            for startup_obj in result["items"]:

                # filter out files
                # ->depending on args, singed by apple, whitelisted, etc
                if isinstance(startup_obj, file.File):

                    # by default, ignore signed by Apple
                    if not args.apple and startup_obj.signed_by_apple:

                        # add to list
                        ignored_items.append(startup_obj)

                # ignore white listed items
                if not args.whitelist and startup_obj.is_whitelisted:

                    # add to list
                    ignored_items.append(startup_obj)

                # now that we are done iterating
                # ->subtract out all ignored/whitelisted items
                result["items"] = list(set(result["items"]) - set(ignored_items))

    # filter out dups in unclassified plugin
    # ->needed since it just looks at the proc list
    remove_dups_from_unclassified(results)

    # get vt results
    if not args.disableVT:

        LOGGER.info("querying VirusTotal - sit tight!")

        # process
        # ->will query VT and add VT info to all files
        virustotal.process_results(results)

    # format output
    # ->normal output or JSON
    formatted_results = output.format_results(results, args.json)

    # show em
    print(formatted_results.encode("utf-8", "xmlcharrefreplace").decode())


def remove_dups_from_unclassified(results) -> None:
    """Filter out dups in unclassified plugin.

    ->needed, since it just looks at the proc list so grabs items that are likely
    detected/classified elsewhere
    """
    # unique unclass'd items
    unique_items = []

    # get unclassifed results
    unclassified_items = [
        result for result in results if result["name"] == "Unclassified Items"
    ]

    # bail if there aren't any
    if not unclassified_items:

        # none
        return

    # just want the dictionary
    # ->first item
    first_unclassified_items = unclassified_items[0]

    # get all hashes
    hashes = all_hashes(results)

    # look at each unclass item
    # ->remove it if its reported elsewhere
    for unclassified_item in first_unclassified_items["items"]:

        # only keep otherwise unknown items
        if hashes.count(unclassified_item.hash) == 0x1:

            # save
            unique_items.append(unclassified_item)

    # update
    first_unclassified_items["items"] = unique_items


def all_hashes(results):
    """Return a list of hashes of all startup items (files)."""
    # list of hashes
    hashes = []

    # iterate over all results
    # ->grab file hashes
    for result in results:

        # hash all files
        for startup_obj in result["items"]:

            # check for file
            if isinstance(startup_obj, file.File):

                # save hash
                hashes.append(startup_obj.hash)

    return hashes


# initialize knockknock
def _init_knockknock(args) -> None:

    if args.verbosity:
        logging.getLogger().setLevel(logging.DEBUG)

    LOGGER.info("initialized logging")

    # get python version
    python_version = sys.version_info

    if (python_version.major, python_version.minor) < _MIN_PYTHON_VERSION:
        raise RuntimeError(f"KnockKnock requires python 3.8+ (found: {python_version})")

    # check macOS version
    if (os_version := utils.get_os_version()) >= _MIN_OS_VERSION:
        LOGGER.info(
            f"{os_version.major}.{os_version.minor} is a supported macOS version"
        )
    else:
        LOGGER.warning(
            f"{os_version.major}.{os_version.minor} is not an officially supported macOS version "
            f"(your mileage may vary)"
        )

    # giving warning about r00t
    if 0 != os.geteuid():
        LOGGER.info("not running as r00t...some results may be missed (e.g. CronJobs)")


# parse args
def _parse_args():

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

    plugin_manager = PluginManager(
        categories_filter={
            _KK_PLUGINS_CATEGORY: plugin_base.KnockKnockPlugin,
        },
        directories_list=[
            str(utils.get_plugins_directory()),
        ],
    )
    assert plugin_manager, "failed to create plugin manager"

    # get all plugins
    plugin_manager.collectPlugins()

    return plugin_manager


def _list_plugins(plugin_manager: PluginManager) -> None:

    LOGGER.info("listing plugins")

    plugins = (
        (plugin.name, Path(plugin.path).name)
        for plugin in plugin_manager.getPluginsOfCategory(_KK_PLUGINS_CATEGORY)
    )

    for plugin_name, module_name in sorted(plugins):
        print(f"{module_name} -> {plugin_name}")


def _scan(*, plugin_name: Optional[str], plugin_manager: PluginManager) -> List[Dict]:

    # results
    results: List[Dict] = []

    # flag indicating plugin was found
    # ->only relevant when a plugin name is specified
    found_plugin = False

    # full scan?
    if not plugin_name:
        LOGGER.info("beginning full scan")

    # plugin only
    else:
        LOGGER.info("beginning scan using %s plugin", plugin_name)

    # iterate over all plugins
    for plugin in plugin_manager.getPluginsOfCategory(_KK_PLUGINS_CATEGORY):

        # results from plugin
        plugin_results = None

        # no plugin names means run 'em all
        if not plugin_name:
            LOGGER.info("executing plugin: %s", plugin.name)

            # execute current plugin
            plugin_results = plugin.plugin_object.scan()

        # try to find match
        else:

            # get name of plugin file as name
            # ->e.g. /plugins/somePlugin.py -> 'somePlugin'
            current_plugin = os.path.split(plugin.path)[1]

            # check for match
            if plugin_name.lower() == current_plugin.lower():

                # found it
                found_plugin = True

                LOGGER.info("executing requested plugin: %s", plugin_name)

                # execute plugin
                plugin_results = plugin.plugin_object.Scan()

        # save plugin output
        if plugin_results:

            # plugins normally return a single dictionary of results
            if isinstance(plugin_results, dict):

                # save results
                results.append(plugin_results)

            # some plugins though can return a list of dictionaries
            # ->e.g. the launch daemon/agent plugin (one dictionary for each type)
            elif isinstance(plugin_results, list):

                # save results
                results.extend(plugin_results)

        # check if specific plugin was specified and found
        # ->if so, can bail
        if plugin_name and found_plugin:

            # bail
            break

    # sanity check
    # -> make sure if a specific plugin was specified, it was found/exec'd
    if plugin_name and not found_plugin:
        LOGGER.error("did not find requested plugin")
        assert not results, "empty results"

    return results


# invoke main interface
if __name__ == "__main__":

    # main interface
    knocknock()
