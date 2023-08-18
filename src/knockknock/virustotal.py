#!/usr/bin/python
#
# KnockKnock by Patrick Wardle is licensed under
# a Creative Commons Attribution-NonCommercial 4.0 International License.
#

import logging
import os
from http import HTTPStatus
from typing import Tuple

import requests

from . import file

LOGGER = logging.getLogger(__name__)

_REQUEST_TIMEOUT = 5  # seconds


def process_results(results):
    """Process results."""

    vt_api_key = os.environ["VT_API_KEY"]

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
                vt_results.update(_query_vt(items, api_key=vt_api_key))

                # reset
                items = []

    # query any remaining items
    if items:
        vt_results.update(_query_vt(items, api_key=vt_api_key))

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
            startup_obj.vt_analysis_stats = vt_results[startup_obj.hash]

    return vt_results


def _query_vt(items, /, *, api_key):
    """Query vt."""
    resources = [item["hash"] for item in items]

    return dict(
        _query_vt_single_resource(resource, api_key=api_key) for resource in resources
    )


def _query_vt_single_resource(resource, /, *, api_key) -> Tuple[str, str]:
    """Query VT for single resource (hash).

    :return: tuple of resource (hash) and vt report.
    """
    url = f"https://www.virustotal.com/api/v3/files/{resource}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    response = requests.get(url, headers=headers, timeout=_REQUEST_TIMEOUT)
    if response.status_code == HTTPStatus.NOT_FOUND:
        response_data = response.json()
        return resource, response_data["error"]["code"]

    assert response.status_code == HTTPStatus.OK

    response_data = response.json()
    return resource, str(response_data["data"]["attributes"]["last_analysis_stats"])
