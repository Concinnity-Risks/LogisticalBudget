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


# For progress bars
from tqdm import tqdm


def analyse(misp_data):
    """
    Programmatically analyse the MISP data

    This is an analysis tool for learning the structure the data

    misp_data - The events and attributes loaded from the MISP server
    """

    print("Analysing MISP data")

    levels = {}
    categories = {}

    events = misp_data["events"]
    attributes = misp_data["attributes"]
    for event in tqdm(events):
        event_id = int(event["id"])
        if event_id in attributes:
            event_attributes = attributes[event_id]
        else:
            event_attributes = []

        levels[event["threat_level_id"]] = True

        for attribute in event_attributes:
            category = attribute["category"]
            if not category in categories:
                categories[category] = {}

            ty = attribute["type"]
            if not ty in categories[category]:
                categories[category][ty] = 0
            else:
                categories[category][ty] += 1

    print("\nResults of analysis: threat level")
    for level in levels.keys():
        print(level)

    print("\nResults of analysis: categories")
    for category in categories.keys():
        print("Category: " + category)
        for ty in sorted(categories[category].keys(), key=lambda x: -categories[category][x]):
            print("    Type: " + ty + " / Count: " +
                  str(categories[category][ty]))
        print("")
