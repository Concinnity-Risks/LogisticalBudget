#!/usr/bin/env python
# -*- coding: utf-8 -*-

def identify_threat_actors(misp_data, initial):
    """
    Generate a dictionary of threat actors in the data

    misp_data - The events and attributes loaded from the MISP server
    initial - The initial dictionary of threat actors
    """

    events = misp_data["events"]

    threat_actors = initial
    for event in events:
        if "GalaxyCluster" in event:
            galaxycluster = event["GalaxyCluster"]
            for galaxy in galaxycluster:
                if "Galaxy" in galaxy:
                    if galaxy["type"] == "threat-actor":
                        threat_actors[galaxy["value"]] = True

    return threat_actors
