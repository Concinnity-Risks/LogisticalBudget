#!/usr/bin/env python
# -*- coding: utf-8 -*-

def identify_threat_actors(misp_data, initial):
    """
    Generate a dictionary of the threat actors within the data

    misp_data - The events and attributes loaded from the MISP server
    initial - The initial dictionary of threat actors
    """
    return identify_galaxy_entries(misp_data, "threat-actor", initial)


def identify_ransomwares(misp_data, initial):
    """
    Generate a dictionary of the threat actors within the data

    misp_data - The events and attributes loaded from the MISP server
    initial - The initial dictionary of ransomwares
    """
    return identify_galaxy_entries(misp_data, "ransomware", initial)


def identify_galaxy_entries(misp_data, galaxy_type, initial):
    """
    Generate a dictionary of the entries in the specified galaxy within the data

    misp_data - The events and attributes loaded from the MISP server
    galaxy_type - The type of the galaxy to look at
    initial - The initial dictionary of entries
    """

    events = misp_data["events"]

    entries = initial
    for event in events:
        if "GalaxyCluster" in event:
            galaxycluster = event["GalaxyCluster"]
            for galaxy in galaxycluster:
                if "Galaxy" in galaxy:
                    if galaxy["type"] == galaxy_type:
                        entries[galaxy["value"]] = True

    return entries
