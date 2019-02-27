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


def generate_general_scatter_plots(misp_data, directory, start_date, end_date):
    """
    Generate general scatter plots for the entire data

    misp_data - The events and attributes loaded from the MISP server
    directory - The name of the directory to store the output in
    start_date - A datetime object with the earliest date of events to be used when scoring,
        use the datetime epoch to ignore the date
    end_date - A datetime object with the latest date of events to be used when scoring,
        use the datetime epoch to ignore the date
    """

    print("Generating general scatter plots")

    if not os.path.exists(directory):
        os.makedirs(directory)

    generate_general_scatter_plot(misp_data, directory + "/scatter-ipsource",
                                  "IPv4 source addresses, binned by the first octet",
                                  "IPv4 source address first octet",
                                  "Number of IPv4 source addresses",
                                  lambda x, y: True,
                                  bin_ipv4_first_octet,
                                  lambda x, y : 1,
                                  lambda x, y : 0.1,
                                  0, 256, start_date, end_date)


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

    print("Generating Threat Actor scatter plots")

    if not os.path.exists("scatter-plot-actors"):
        os.makedirs("scatter-plot-actors")

    generate_scatter_plots_by_entry(misp_data, directory, "threat-actor", "threat actor",
                                    lambda entry : "IPv4 source addresses, binned by the first six bits, used by " + entry,
                                    "IPv4 source address first six bits",
                                    "Number of IPv4 source addresses",
                                    filter_by_entry, bin_ipv4_first_six_bits,
                                    lambda x, y : 1,
                                    lambda x, y : 10,
                                    0, 64, start_date, end_date)


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

    print("Generating Ransomware scatter plots")

    if not os.path.exists("scatter-plot-ransomware"):
        os.makedirs("scatter-plot-ransomware")

    generate_scatter_plots_by_entry(misp_data, directory, "ransomware", "ransomware",
                                    lambda entry : "IPv4 source addresses, binned by the first six bits, used by " + entry,
                                    "IPv4 source address first six bits",
                                    "Number of IPv4 source addresses",
                                    filter_by_entry, bin_ipv4_first_six_bits,
                                    lambda x, y : 1,
                                    lambda x, y : 10,
                                    0, 64, start_date, end_date)


def filter_by_entry(galaxy_type, entry, event, attributes):
    """
    A filter that determines whether the event matches the specified threat actor or ransomware

    galaxy_type - The galaxy type to filter on
    entry - The specific threat actor or ransomware to filter on
    event - The event to query
    attributes - The attributes associated with the event to query

    Returns: True if the event matches, and false otherwise
    """

    # Identify the entry in the event
    event_entry = utility.identify_entry(galaxy_type, event)

    if event_entry == entry:
        return True

    return False


def bin_ipv4_first_six_bits(event, attribute):
    """
    Returns: The first octet of an associated IPv4 address, or -1 if no IPv4 was found
    """

    if attribute["category"] == "Network activity" or attribute["category"] == "Payload delivery":
        ty = attribute["type"]
        if ty == "ip-src":
            addr = attribute["value"].split(".")
            if len(addr) == 4:
                addr_bin = attribute["value"].split(".")[0]
                try:
                    return int(addr_bin) >> 2
                except ValueError:
                    return -1

    return -1


def bin_ipv4_first_octet(event, attribute):
    """
    Returns: The first octet of an associated IPv4 address, or -1 if no IPv4 was found
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


def generate_general_scatter_plot(misp_data, filename,
        plot_title, x_axis_title, y_axis_title,
        filter_function, bin_function, primary_score_function, secondary_score_function,
        min_bin, max_bin, start_date, end_date):
    """
    Generate a scatter plot for each entry (e.g. threat actor or ransomware)

    misp_data - The events and attributes loaded from the MISP server
    filename - The name of the file to store the output in
    plot_title_function - A function that takes an entry and generates a plot title for it
    x_axis_title - The description of the x-axis
    y_axis_title - The description of the y-axis
    filter_function - The function that determines whether to inspect the event+attribute-set or not
    bin_function - The function that identifies which bin to filter each event+attribute-set into
    primary_score_function - The function that determines the y-coordinate of the splat
    secondary_score_function - The function that determines the size of the splat
    min_bin - The minimum bin value (the lhs of the x-axis)
    max_bin - The maximum bin value (the rhs of the x-axis)
    start_date - A datetime object with the earliest date of events to be used when scoring,
        use the datetime epoch to ignore the date
    end_date - A datetime object with the latest date of events to be used when scoring,
        use the datetime epoch to ignore the date
    """

    events = misp_data["events"]
    attributes = misp_data["attributes"]

    epoch = datetime.datetime.utcfromtimestamp(0)

    # Generate an initial collection of src-ip bins
    #
    score = []
    size = []
    for bin in range(min_bin, max_bin):
        score.append(0)
        size.append(0)

    # Scan all of the events
    #
    for event in tqdm(events):
        event_id = int(event["id"])

        if event_id in attributes:
            event_attributes = attributes[event_id]
        else:
            event_attributes = []

        if filter_function(event, event_attributes):
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
                        # The event fits out filters: update the score accordingly
                        #
                        for attribute in event_attributes:
                            bin = bin_function(event, attribute)
                            if bin != -1:
                                score[bin] += primary_score_function(event, attribute)
                                size[bin] += secondary_score_function(event, attribute)
                                # size[bin] += 0.1

    # Now plot the graph
    #
    trace = graph_objs.Scatter(
        y=score,
        mode='markers',
        marker=dict(
            size=size,
            color=score,
            colorscale='Viridis',
            showscale=True
        )
    )
    data = [trace]
    layout = dict(
        title=plot_title,
        xaxis=dict(title=x_axis_title),
        yaxis=dict(title=y_axis_title))
    fig = dict(data=data, layout=layout)

    plotly.offline.plot(fig, filename=filename + ".html",
                        auto_open=False, show_link=False)


def generate_scatter_plots_by_entry(misp_data, directory, galaxy_type, entry_description,
        plot_title_function, x_axis_title, y_axis_title,
        filter_function, bin_function, primary_score_function, secondary_score_function,
        min_bin, max_bin, start_date, end_date):
    """
    Generate a scatter plot for each entry (e.g. threat actor or ransomware)

    misp_data - The events and attributes loaded from the MISP server
    directory - The name of the directory to store the output in
    galaxy_type - The type of the galaxy to look at
    entry_description - How we refer to the galaxy type in human-readable terms
    plot_title_function - A function that takes an entry and generates a plot title for it
    x_axis_title - The description of the x-axis
    y_axis_title - The description of the y-axis
    filter_function - The function that determines whether to inspect the event+attribute-set or not
    bin_function - The function that identifies which bin to filter each event+attribute-set into
    primary_score_function - The function that determines the y-coordinate of the splat
    secondary_score_function - The function that determines the size of the splat
    min_bin - The minimum bin value (the lhs of the x-axis)
    max_bin - The maximum bin value (the rhs of the x-axis)
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
    size = []
    for bin in range(min_bin, max_bin):
        score.append(0)
        size.append(0)

    # Generate a graph for each entry
    #
    for entry in tqdm(entries):
        # Construct a filename for the output
        filename = directory + "/scatter-" + entry

        # Scan all of the events
        #
        for event in events:
            event_id = int(event["id"])

            if event_id in attributes:
                event_attributes = attributes[event_id]
            else:
                event_attributes = []

            if filter_function(galaxy_type, entry, event, event_attributes):
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
                                bin = bin_function(event, attribute)
                                if bin != -1:
                                    score[bin] += primary_score_function(event, attribute)
                                    size[bin] += secondary_score_function(event, attribute)

        # Now plot the graph
        #
        trace = graph_objs.Scatter(
            y=score,
            mode='markers',
            marker=dict(
                size=size,
                color=score,
                colorscale='Viridis',
                showscale=True
            )
        )
        data = [trace]
        layout = dict(
            title=plot_title_function(entry),
            xaxis=dict(title=x_axis_title),
            yaxis=dict(title=y_axis_title))
        fig = dict(data=data, layout=layout)

        plotly.offline.plot(fig, filename=filename + ".html",
                            auto_open=False, show_link=False)
