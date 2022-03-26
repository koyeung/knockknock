#!/usr/bin/python
#
# KnockKnock by Patrick Wardle is licensed under
# a Creative Commons Attribution-NonCommercial 4.0 International License.
#

import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request

from . import file

LOGGER = logging.getLogger(__name__)

# query URL
_VT_URL = "https://www.virustotal.com/partners/sysinternals/file-reports?apikey="

# API key
_VT_API_KEY = "bef728a398d7b666c5fbdc6f64671161284ef49c23e270ac540ada64893b433b"


def process_results(results):
    """Process results."""

    vt_results = {}

    # item (files) to query
    # ->grab up to 25 before making a query!
    items = []

    # queried startup items
    queried_items = set()

    # process items, 25 at a time
    for result in results:

        # iterate over each plugin's results
        for startup_obj in result["items"]:

            # data for item (file)
            item_data = {}

            # only process files
            # ->note, plugins don't be mixed item items, so can bail here
            if not isinstance(startup_obj, file.File):

                # stop processing this item group
                break

            # skip items that don't have hashes
            if not startup_obj.hash:

                # skip
                continue

            # skip values that already have been queried
            if startup_obj.hash in queried_items:

                # skip
                continue

            # auto start location
            item_data["autostart_location"] = result["name"]

            # set item name
            item_data["autostart_entry"] = startup_obj.name

            # set item path
            item_data["image_path"] = startup_obj.path

            # set hash
            item_data["hash"] = startup_obj.hash

            # set creation times
            item_data["creation_datetime"] = os.path.getctime(startup_obj.path)

            # add item info to list
            items.append(item_data)

            # save in set of queried items
            queried_items.add(startup_obj.hash)

            # when we've got 25
            # ->query VT
            if 25 == len(items):

                # query
                vt_results.update(_query_vt(items))

                # reset
                items = []

    # query any remaining items
    if items:

        # query
        vt_results.update(_query_vt(items))

    # (re)iterate over all detected items (results)
    # ->any that were queried add the VT results
    for result in results:

        # iterate over each plugin's results
        for startup_obj in result["items"]:

            # skip non-item files, or items that weren't queried
            if (
                not isinstance(startup_obj, file.File)
                or startup_obj.hash not in queried_items
            ):

                # skip
                continue

            # skip items that didn't get a response
            if startup_obj.hash not in vt_results:

                # skip
                continue

            # add VT results to item
            startup_obj.vt_ratio = vt_results[startup_obj.hash]

    return vt_results


def _query_vt(items):
    """Query vt."""

    query_results = {}

    # headers
    request_headers = {}

    # set content type
    request_headers["Content-Type"] = "application/json"

    # set user agent
    request_headers["User-Agent"] = "VirusTotal"

    # wrap
    try:

        # build request
        request = urllib.request.Request(
            _VT_URL + _VT_API_KEY,
            json.dumps(items, indent=4).encode("utf-8"),
            headers=request_headers,
        )

        # make request
        with urllib.request.urlopen(request) as response:

            # convert response to JSON
            vt_response = json.loads(response.read())

        # process response
        # ->should be a list of items, within the 'data' key
        if "data" in vt_response:

            # process/parse all
            for item in vt_response["data"]:

                # process
                _put_item_to_results(item, results=query_results)

    # exceptions
    # ->ignore (likely network related)
    except Exception:  # pylint: disable=broad-except
        LOGGER.exception("failed to query virustotal")

    return query_results


# process a single result
#  ->save parse/save info
def _put_item_to_results(item, /, *, results) -> None:

    # extract found flag
    found = item["found"]

    # extract hash
    hash_ = item["hash"]

    # when item is found
    # ->save detection ratio
    if found:

        # save detection ratio
        results[hash_] = item["detection_ratio"]

    # otherwise indicate it wasn't found
    else:

        # not found
        results[hash_] = "not found"
