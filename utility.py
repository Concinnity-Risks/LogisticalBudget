#!/usr/bin/env python
# -*- coding: utf-8 -*-

def identify_threat_actors(misp_data, initial):
    """
    Generate a dictionary of the threat actors within the data

    misp_data - The events and attributes loaded from the MISP server
    initial - The initial dictionary of threat actors

    Returns: A dictionary of the threat actor entries present in the data
    """
    return identify_galaxy_entries(misp_data, "threat-actor", initial)


def identify_ransomwares(misp_data, initial):
    """
    Generate a dictionary of the threat actors within the data

    misp_data - The events and attributes loaded from the MISP server
    initial - The initial dictionary of ransomwares

    Returns: A dictionary of the ransomware entries present in the data
    """
    return identify_galaxy_entries(misp_data, "ransomware", initial)


def identify_galaxy_entries(misp_data, galaxy_type, initial):
    """
    Generate a dictionary of the entries in the specified galaxy within the data

    misp_data - The events and attributes loaded from the MISP server
    galaxy_type - The type of the galaxy to look at
    initial - The initial dictionary of entries

    Returns: A dictionary of the entries present in the data
    """

    events = misp_data["events"]

    entries = initial
    for event in events:
        event_entry = identify_entry(galaxy_type, event)
        if event_entry != "Unattributed":
            entries[event_entry] = True

    return entries


def identify_entry(galaxy_type, event):
    """
    Identify the entry (e.g. threat actor or ransomware, based on galaxy) associated with an event

    galaxy_type - The type of the galaxy to look at
    event - The event to be inspected

    Returns: The entry associated with the event, or "Unattributed" if the event was not attributed to an entry
    """

    event_entry = "Unattributed"

    if "GalaxyCluster" in event:
        galaxycluster = event["GalaxyCluster"]
        for galaxy in galaxycluster:
            if "Galaxy" in galaxy:
                if galaxy["type"] == galaxy_type:
                    event_entry = galaxy["value"]

    return event_entry
