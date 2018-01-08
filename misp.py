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


def get_misp_data(misp, use_cache):
    """
    Query events and attributes from the server, but if requested use the cache where possible

    misp: The MISP server connection object
    use_cache: True if the data from the cache should be uses in preference
    """

    misp_data = {
        "events": {},
        "attributes": {},
    }

    if use_cache:
        try:
            # Try reading from the cache first
            misp_data = caching.read_cache()
        except FileNotFoundError:
            print("Cache data file not found")
            pass

    warnings = []

    # Obtain the data from the MISP server
    #
    try:
        # Get events
        #
        print("Obtaining events from " + ("cache" if caching else "server"))
        events = misp_data["events"]
        if not use_cache or len(misp_data["events"]) == 0:
            r = misp.get_index(filters=None)
            if r.get('errors'):
                print("Warning: Errors from get_index() call")
                print(r["errors"])
            events = r["response"]

        # Get attributes associated with each event
        #
        print("Obtaining attributes from " + ("cache (and maybe the server)" if caching else "server"))
        attributes = misp_data["attributes"]
        try:
            for event in tqdm(events):
                event_id_str = event["id"]
                event_id = int(event_id_str)
                if not event_id in attributes:
                    kwargs = {"controller": "attributes",
                              "eventid": event_id_str}
                    attrs = search(misp=misp, **kwargs)

                    if "Attribute" in attrs:
                        attributes[event_id] = attrs["Attribute"]
                    else:
                        warnings.append("Warning: Attributes for event " + event_id_str +
                                        " were in unexpected format " + str(attrs))
                        attributes[event_id] = attrs

        except KeyboardInterrupt:
            # Sometimes the user get bored, in which case stop obtaining
            # attributes, but otherwise continue
            print("\nStopped retrieving attribute data due to keyboard interrupt")

        misp_data = {
            "events": events,
            "attributes": attributes,
        }

        if use_cache:
            caching.write_cache(misp_data)

    except Exception as e:
        print(repr(e))

        misp_data = {
            "events": events,
            "attributes": attributes,
        }

        if use_cache:
            caching.write_cache(misp_data)

    # Emit collected warnings
    #
    for warning in warnings:
        print(warning)

    return misp_data
