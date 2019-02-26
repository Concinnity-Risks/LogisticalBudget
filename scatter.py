#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Standard Python imports
#
import os
import subprocess
import math
import datetime

# For progress bars
from tqdm import tqdm

# For generating scatter plots
#
import plotly
import plotly.graph_objs as graph_objs
import numpy as np

# Modules directly associated with this application
#
import scoring
import utility


def generate_threat_actor_scatter_plots(misp_data, directory, start_date, end_date):
    """
    Generate a scatter plot for each threat actor

    misp_data - The events and attributes loaded from the MISP server
    directory - The name of the directory to store the output in
    start_date - A datetime object with the earliest date of events to be used when scoring,
        use the datetime epoch to ignore the date
    end_date - A datetime object with the latest date of events to be used when scoring,
        use the datetime epoch to ignore the date
    """

    generate_scatter_plots(misp_data, directory, "threat-actor",
                           "threat actor", start_date, end_date)


def generate_ransomware_scatter_plots(misp_data, directory, start_date, end_date):
    """
    Generate a scatter plot for each ransomware

    misp_data - The events and attributes loaded from the MISP server
    directory - The name of the directory to store the output in
    start_date - A datetime object with the earliest date of events to be used when scoring,
        use the datetime epoch to ignore the date
    end_date - A datetime object with the latest date of events to be used when scoring,
        use the datetime epoch to ignore the date
    """

    generate_scatter_plots(misp_data, directory, "ransomware",
                           "ransomware", start_date, end_date)


def bin_ipv4_first_octet(event, attribute):
    """
    Returns the first octet of an associated IPv4 address, or -1 if no IPv4 was found
    """

    if attribute["category"] == "Network activity" or attribute["category"] == "Payload delivery":
        ty = attribute["type"]
        if ty == "ip-src":
            addr = attribute["value"].split(".")
            if len(addr) == 4:
                addr_bin = attribute["value"].split(".")[0]
                try:
                    return int(addr_bin)
                except ValueError:
                    return -1

    return -1


def generate_scatter_plots(misp_data, directory, galaxy_type, entry_description, start_date, end_date):
    """
    Generate a score card for each entry (e.g. threat actor or ransomware)

    misp_data - The events and attributes loaded from the MISP server
    directory - The name of the directory to store the output in
    galaxy_type - The type of the galaxy to look at
    entry_description - How we refer to the galaxy type in human-readable terms
    start_date - A datetime object with the earliest date of events to be used when scoring,
        use the datetime epoch to ignore the date
    end_date - A datetime object with the latest date of events to be used when scoring,
        use the datetime epoch to ignore the date
    """

    events = misp_data["events"]
    attributes = misp_data["attributes"]

    epoch = datetime.datetime.utcfromtimestamp(0)

    # Generate dictionary of entries (e.g. Threat Actors or Ransomware)
    entries = utility.identify_galaxy_entries(
        misp_data, galaxy_type, initial={})

    # Give up if we found no relevant entries in the data
    if not entries:
        print("No entries found")
        return

    # Generate an initial collection of src-ip bins
    #
    score = []
    for bin in range(0, 256):
        score.append(0)

    # Generate a graph for each entry
    #
    for entry in tqdm(entries):
        # Construct a filename for the output
        filename = directory + "/scatter-" + entry

        # Construct a title for the graph
        title = "IPv4 source addresses, binned by IPv4 first octet, used by " + entry

        # Scan all of the events
        #
        for event in events:
            event_id = int(event["id"])

            # Identify the entry in the event
            #
            unattributed = "Unattributed"
            event_entry = unattributed

            if "GalaxyCluster" in event:
                galaxycluster = event["GalaxyCluster"]
                for galaxy in galaxycluster:
                    if "Galaxy" in galaxy:
                        if galaxy["type"] == galaxy_type:
                            event_entry = galaxy["value"]

            # If the event relates to the entry we are currently graphing, then collate the event's data
            #
            if event_entry == entry:
                if event_id in attributes:
                    event_attributes = attributes[event_id]
                else:
                    event_attributes = []

                if "timestamp" in event:
                    seconds_since_epoch = int(event["timestamp"])
                    if seconds_since_epoch > 1:
                        event_time = datetime.datetime.fromtimestamp(
                            seconds_since_epoch)

                        reject = False
                        if start_date != epoch and event_time < start_date:
                            reject = True
                        if end_date != epoch and event_time > end_date:
                            reject = True

                        if not reject:
                            # The event is for the entry we are graphing, and fits out filters, so
                            # scan the attributes and update the scores accordingly
                            #
                            for attribute in event_attributes:
                                bin = bin_ipv4_first_octet(event, attribute)
                                if bin != -1:
                                    score[bin] += 1

        # Now plot the graph
        #
        trace = graph_objs.Scatter(
            y=score,
            mode='markers',
            marker=dict(
                size=16,
                color=score,
                colorscale='Hot',
                showscale=True
            )
        )
        data = [trace]
        layout = dict(
            title=title,
            xaxis=dict(title="IPv4 address first octet"),
            yaxis=dict(title="Number of IPv4 source addresses"))
        fig = dict(data=data, layout=layout)

        plotly.offline.plot(fig, filename=filename + ".html",
                            auto_open=False, show_link=False)
