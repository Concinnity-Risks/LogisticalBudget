#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2018 Éireann Leverett and Bruce Stenning
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import caching

# For progress bars
from tqdm import tqdm


def search(misp, **kwargs):
    """
    Search the MISP server and return records that match

    misp: The MISP server connection object
    kwargs: The specification of the search (e.g. controller="attributes", org="CIRCL")
    """

    res = {}

    try:
        r = misp.search(**kwargs)
        if r.get('errors'):
            print("Warning: Errors from get_all_attributes_txt() call")
            print(r["errors"])
        res = r['response']
    except ValueError as e:
        print(e)

    return res


def get_misp_data(misp, force_download):
    """
    Query events and attributes from the server, using cached data where available

    misp: The MISP server connection object
    force_download: Force download of all attributes from the server (this can be slow)
    """

    misp_data = {
        "events": {},
        "attributes": {},
    }

    try:
        # Try reading from the cache first
        misp_data = caching.read_cache()
    except FileNotFoundError:
        print("Cache data file not found")
        pass

    warnings = []

    # Obtain the data from the MISP server
    #
    print("Obtaining events...")
    cached_events = misp_data["events"]
    r = misp.get_index(filters=None)
    if r.get('errors'):
        print("Warning: Errors from get_index() call")
        print(r["errors"])
    updated_events = r["response"]

    # Get attributes associated with each event
    #
    print("Obtaining attributes...")
    updated_attributes = misp_data["attributes"]
    for event in tqdm(updated_events):
        if force_download or cached_events == {} or not event in cached_events:
            event_id_str = event["id"]
            event_id = int(event_id_str)
            if not event_id in updated_attributes:
                kwargs = {"controller": "attributes",
                          "eventid": event_id_str}
                attrs = search(misp=misp, **kwargs)

                if "Attribute" in attrs:
                    updated_attributes[event_id] = attrs["Attribute"]
                else:
                    warnings.append("Warning: Attributes for event " + event_id_str +
                                    " were in unexpected format " + str(attrs))
                    updated_attributes[event_id] = attrs

    misp_data = {
        "events": updated_events,
        "attributes": updated_attributes,
    }

    caching.write_cache(misp_data)

    # Emit collected warnings
    #
    for warning in warnings:
        print(warning)

    return misp_data
