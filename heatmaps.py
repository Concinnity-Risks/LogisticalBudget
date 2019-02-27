#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Standard Python imports
#
import os
import subprocess
import datetime
import math

# For progress bars
from tqdm import tqdm

# For heat map plotting
#
import plotly
import plotly.graph_objs as graph_objs

# Modules directly associated with this application
#
import scoring
import utility


def generate_heatmaps(misp_data, directory, num_days, bin_size, bin_name):
    """
    Generate heatmaps for various criteria

    misp_data - The events and attributes loaded from the MISP server
    directory - The name of the directory to store the output in
    num_days - The number of days to graph
    bin_size - The number of days in each graph block
    bin_name - The name for a graph block
    """

    if not os.path.exists(directory):
        os.makedirs(directory)

    sets = []
    for html in [True, False]:
        sets.append(
            {"num_days": num_days,
             "bin_size": bin_size,
             "scoring_function": scoring.score_by_event_count,
             "scoring_name": "Threat actor events",
             "filename": directory + "/heatmap-count-" + bin_name,
             "use_plotly": html
             })
        sets.append(
            {"num_days": num_days,
             "bin_size": bin_size,
             "scoring_function": scoring.score_by_event_threat_level,
             "scoring_name": "Sum of event threat levels (high = 100, medium = 50, low = 1)",
             "filename": directory + "/heatmap-levels-" + bin_name,
             "use_plotly": html
             })
        sets.append(
            {"num_days": num_days,
             "bin_size": bin_size,
             "scoring_function": scoring.score_by_source_ips,
             "scoring_name": "Number of source IP addresses implicated",
             "filename": directory + "/heatmap-ipsrc-" + bin_name,
             "use_plotly": html
             })
        sets.append(
            {"num_days": num_days,
             "bin_size": bin_size,
             "scoring_function": scoring.score_by_destination_ips,
             "scoring_name": "Number of destination IP addresses implicated",
             "filename": directory + "/heatmap-ipdst-" + bin_name,
             "use_plotly": html
             })
        sets.append(
            {"num_days": num_days,
             "bin_size": bin_size,
             "scoring_function": scoring.score_by_domain_count,
             "scoring_name": "Number of domains implicated",
             "filename": directory + "/heatmap-domains-" + bin_name,
             "use_plotly": html
             })
        sets.append(
            {"num_days": num_days,
             "bin_size": bin_size,
             "scoring_function": scoring.score_by_malware_files,
             "scoring_name": "Numbers of malware files recorded",
             "filename": directory + "/heatmap-files-" + bin_name,
             "use_plotly": html
             })
        sets.append(
            {"num_days": num_days,
             "bin_size": bin_size,
             "scoring_function": scoring.score_by_amount_of_external_analysis,
             "scoring_name": "Amount of external analysis recorded",
             "filename": directory + "/heatmap-analysis-" + bin_name,
             "use_plotly": html
             })

    for set in tqdm(sets):
        generate_by_threat_actor(misp_data, **set)


def generate_by_threat_actor(misp_data, num_days, bin_size, scoring_function, scoring_name, filename, use_plotly):
    """
    Generate a heat map for each threat actor, and save either as HTML or as a gnuplot input file and PNG

    misp_data - The events and attributes loaded from the MISP server
    num_days - The total number of days to generate the heat map for
    bin_size - The number of days to bin events into (e.g. 7 to put them into weekly bins)
    scoring_function - Function to score an event and its attributes
    scoring_name - A string to describe the scoring of the event
    filename - The name of the file to write the heatmap to
    use_plotly - True to use plotly for the rendering, False to output data for gnuplot
    """

    events = misp_data["events"]
    attributes = misp_data["attributes"]

    title = scoring_name + " per " + str(bin_size) + " day period"

    # Find the latest event in the data
    #
    time_base = datetime.datetime.utcfromtimestamp(0)
    for event in events:
        if "timestamp" in event:
            seconds_since_epoch = int(event["timestamp"])
            if seconds_since_epoch > 1:
                event_time = datetime.datetime.fromtimestamp(seconds_since_epoch)
                if event_time > time_base:
                    time_base = event_time

    # Generate dictionary of threat actors
    #
    unattributed = "Unattributed"
    threat_actors = utility.identify_threat_actors(misp_data, initial={unattributed: True})

    # Construct an initial table of actors and zero scores
    #
    rows = {}
    for actor in threat_actors.keys():
        rows[actor] = []
        for d in range(math.ceil(num_days / bin_size)):
            rows[actor].append(0)

    # Scan the events by actor and timestamp
    #
    for event in events:
        event_id = int(event["id"])
        if event_id in attributes:
            event_attributes = attributes[event_id]
        else:
            event_attributes = []

        # Identify the threat actor in the event
        event_actor = utility.identify_entry("threat-actor", event)

        if "timestamp" in event:
            seconds_since_epoch = int(event["timestamp"])
            if seconds_since_epoch > 1:
                event_time = datetime.datetime.fromtimestamp(
                    seconds_since_epoch)
                event_age = time_base - event_time
                if event_age.days < num_days:
                    score = scoring_function(event, event_attributes)
                    rows[event_actor][int(event_age.days / bin_size)] += score

    # Remove the unattributed row, as it dwarfs data from the attributed events
    threat_actors.pop(unattributed, None)

    # Remove all actors with no activity logged
    #
    actors_to_remove = []

    for actor in threat_actors.keys():
        some_activity = False
        for freq in rows[actor]:
            if freq != 0:
                some_activity = True
        if not some_activity:
            actors_to_remove.append(actor)

    for actor in actors_to_remove:
        threat_actors.pop(actor, None)

    # Sort the threat actors by aggregate score, so that the most active
    # are at the bottom of the chart
    #
    sorted_threat_actors = []
    sorted_rows = []
    for key, value in sorted(threat_actors.items(), key=lambda x: sum(rows[x[0]])):
        sorted_threat_actors.append(key)
        sorted_rows.append(rows[key])

    # Now plot the graph
    #
    if use_plotly:
        date_list = [time_base - datetime.timedelta(days=x)
                     for x in range(0, num_days, bin_size)]

        frequency_data = []
        for row in sorted_rows:
            frequency_data.append(list(row))

        data = [
            graph_objs.Heatmap(
                z=frequency_data,
                x=date_list,
                y=sorted_threat_actors,
                colorscale="Hot",
            )
        ]

        layout = graph_objs.Layout(
            title=title,
            xaxis=dict(ticks="", nticks=36),
            yaxis=dict(ticks="")
        )

        fig = graph_objs.Figure(data=data, layout=layout)
        plotly.offline.plot(fig, filename=filename + ".html",
                            auto_open=False, show_link=False)
    else:
        if not threat_actors:
            print("Info: No threat actors found for heatmap '" + title + "'")
        else:
            height = len(sorted_threat_actors)
            width = len(sorted_rows[0])

            minz = 1.0e9
            maxz = -1.0e9
            for row in sorted_rows:
                for datum in row:
                    if datum < minz:
                        minz = datum
                    if datum > maxz:
                        maxz = datum

            with open(filename + ".plt", "w") as outfile:
                # Set the size of the output image
                outfile.write("set terminal png size 1280, 1024\n")

                # Set the filename of the output image
                outfile.write("set output \"" + filename + ".png\"\n")

                # Set the title of the graph
                outfile.write("set title \"" + title + "\"\n")

                # Label the score map
                outfile.write("set cblabel \"" + scoring_name + "\"\n")

                # Don't draw a key because this is going to be a heatmap
                outfile.write("unset key\n")

                # Produce a 2D heatmap, not a 3D surface plot
                #
                outfile.write("set view map scale 1\n")
                outfile.write("set style data lines\n")

                # Turn off tic marks
                outfile.write("set tics scale 0\n")

                # Set the left margin so that threat actor names are not truncated
                outfile.write("set lmargin 15\n")

                # Specify the labels for the X-axis, i.e. the dates
                #
                outfile.write("set xtics (")
                every_n_bins = 2
                i = 0
                for days in range(0, num_days, bin_size * every_n_bins):
                    stamp = time_base - \
                        datetime.timedelta(days=(num_days - days))
                    date = str(stamp.day) + "/" + \
                        str(stamp.month) + "/" + str(stamp.year)
                    outfile.write("\"" + date + "\" " + str(i) + ", ")
                    i += every_n_bins
                outfile.write(")\n")

                # Specify the labels for the Y-axis, i.e. the threat actors
                #
                outfile.write("set ytics (")
                i = 0
                for actor in sorted_threat_actors:
                    outfile.write("\"" + actor + "\" " + str(i) + ", ")
                    i += 1
                outfile.write(")\n")

                # Set the ranges of the data that will be plot
                #
                outfile.write(
                    "set xrange [ -0.5 : " + str(width - 0.5) + " ]\n")
                outfile.write(
                    "set yrange [ -0.5 : " + str(height - 0.5) + " ]\n")
                outfile.write(
                    "set zrange [ " + str(minz) + " : " + str(maxz) + " ]\n")
                outfile.write(
                    "set cbrange [ " + str(minz) + " : " + str(maxz) + " ]\n")

                # Set the heatmap palette
                #
                outfile.write(
                    "set palette defined (0 \"black\", 0.33 \"red\", 0.66 \"yellow\", 1 \"white\")\n")

                # Now write out the data for the heatmap
                #
                outfile.write("$map1 << EOD\n")

                for row in sorted_rows:
                    for datum in reversed(row):
                        outfile.write(str(datum) + " ")
                    outfile.write("\n")

                # gnuplot seems to want an extra row of data for some reason.
                # I have a suspicion that this is something to do with interpolation
                # of values, if you happened to set that -- but we don't.
                #
                for datum in range(width):
                    outfile.write("0 ")
                outfile.write("\n")

                # End the data and plot the heatmap
                #
                outfile.write("EOD\n")
                outfile.write("splot \"$map1\" matrix with image\n")

            try:
                process = subprocess.Popen(
                    args=["gnuplot", filename + ".plt"],
                    stdout=subprocess.PIPE)
                output = process.communicate()[0].decode("utf-8")
                if len(output) != 0:
                    print(output)
            except Exception as e:
                print("Unable to run gnuplot: Is it installed?  " + repr(e))
