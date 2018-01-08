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


import pickle
import pprint
from tqdm import tqdm


def write_cache(events):
    with open("cache.obj", "wb") as outfile:
        pickle.dump(events, outfile)


def read_cache():
    with open("cache.obj", "rb") as infile:
        events = pickle.load(infile)
    return events


def dump_cache():
    try:
        misp_data = read_cache()
    except FileNotFoundError:
        raise ValueError("No cache file found")

    errors = []
    with open("cache.txt", "w") as outfile:
        pp = pprint.PrettyPrinter(indent=4, stream=outfile)

        for event in tqdm(misp_data["events"]):
            event_id = int(event["id"])

            try:
                pp.pprint(event)
                outfile.write("\n")
            except UnicodeEncodeError:
                errors.append("Unicode error in Event " + str(event_id))

            attributes = misp_data["attributes"]
            if event_id in attributes:
                attribute = attributes[event_id]
                try:
                    pp.pprint(attribute)
                    outfile.write("\n")
                except UnicodeEncodeError:
                    errors.append(
                        "Unicode error in Attribute " + str(event_id))

    print("\n")
    for error in errors:
        print(error)
