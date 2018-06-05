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

# Modules directly associated with this application
#
import scoring
import utility


# TODO: More representative scoring functions


def generate_threat_actor_scorecards(misp_data, start_date, end_date):
    """
    Generate a score card for the specified threat actor

    misp_data - The events and attributes loaded from the MISP server
    start_date - A datetime object with the earliest date of events to be used when scoring,
        use the datetime epoch to ignore the date
    end_date - A datetime object with the latest date of events to be used when scoring,
        use the datetime epoch to ignore the date
    """

    events = misp_data["events"]
    attributes = misp_data["attributes"]

    epoch = datetime.datetime.utcfromtimestamp(0)

    # Generate dictionary of threat actors
    threat_actors = utility.identify_threat_actors(misp_data, initial={})

    # Set up the score characteristics
    #
    score_descriptions = {
        "team_size": "Team Size",
        "resource_cost": "Resource Cost",
        "time_cost": "Time Cost",
        "logistical_budget": "Logistical Budget"
    };

    score_colour = {
        "team_size": "orange",
        "resource_cost": "red",
        "time_cost": "blue",
        "logistical_budget": "black"
    };

    score_units = {
        "team_size": "People",
        "resource_cost": "$",
        "time_cost": "Years",
        "logistical_budget": ""
    };

    score_range = {
        "team_size": 500,
        "resource_cost": 1000000,
        "time_cost": 3,
        "logistical_budget": 1000
    };

    score_type = { # linear or log
        "team_size": "log",
        "resource_cost": "log",
        "time_cost": "log",
        "logistical_budget": "log"
    };

    # Unlike the heatmap scores, which are used for comparative analysis of the threat actors, this
    # is a bit more complex in that the scores are intended to be absolutes in specific units.
    #
    score_multiplier = {
        "team_size": 40,
        "resource_cost": 50000,
        "time_cost": 0.1,
        "logistical_budget": 50.0
    };

    score_fuzz = {
        "team_size": 0.25,
        "resource_cost": 0.25,
        "time_cost": 0.25,
        "logistical_budget": 0.05
    };

    # This will be filled in later, when the palette is constructed
    score_palette_offset = {}

    # Generate an initial collection of score cards
    #
    scorecards = {}
    for actor in threat_actors:
        scorecards[actor] = {
            "team_size": 0,
            "resource_cost": 0,
            "time_cost": 0,
            "logistical_budget": 0
        };

    # Scan the events by actor and timestamp
    #
    for event in tqdm(events):
        event_id = int(event["id"])
        if event_id in attributes:
            event_attributes = attributes[event_id]
        else:
            event_attributes = []

        unattributed = "Unattributed"
        event_actor = unattributed

        if "GalaxyCluster" in event:
            galaxycluster = event["GalaxyCluster"]
            for galaxy in galaxycluster:
                if "Galaxy" in galaxy:
                    if galaxy["type"] == "threat-actor":
                        event_actor = galaxy["value"]

        if event_actor != unattributed:
            if "timestamp" in event:
                seconds_since_epoch = int(event["timestamp"])
                if seconds_since_epoch > 1:
                    event_time = datetime.datetime.fromtimestamp(seconds_since_epoch)

                    reject = False
                    if start_date != epoch and event_time < start_date:
                        reject = True
                    if end_date != epoch and event_time > end_date:
                        reject = True

                    if not reject:
                        scorecards[event_actor]["team_size"] += scoring.score_team_size(event, event_attributes)
                        scorecards[event_actor]["resource_cost"] += scoring.score_resource_cost(event, event_attributes)
                        scorecards[event_actor]["time_cost"] += scoring.score_time_cost(event, event_attributes)
                        scorecards[event_actor]["logistical_budget"] += scoring.score_logistical_budget(event, event_attributes)

    # Now generate our score card as a sumple text output for now
    #
    if False:
        for actor in threat_actors:
            print("Score card for threat actor: " + actor)
            print("")
            print("Team size:          " + str(scorecards[actor]["team_size"]))
            print("Resource cost:      " + str(scorecards[actor]["resource_cost"]))
            print("Time cost:          " + str(scorecards[actor]["time_cost"]))
            print("Logistical budget:  " + str(scorecards[actor]["logistical_budget"]))
            print("")

    # Generate a chart for each threat actor
    #
    if not threat_actors:
        print("No threat actors")
    else:
        height = len(threat_actors)

        for actor in threat_actors:
            filename = "scorecards/scorecard-" + actor
            with open(filename + ".plt", "w") as outfile:
                # Set the size of the output image (though note that it will be rotated)
                outfile.write("set terminal png size 720, 1280\n")

                # Set the filename of the output image
                outfile.write("set output \"" + filename + ".tmp.png\"\n")

                # Don't draw a key or a colour box
                #
                outfile.write("unset key\n")
                outfile.write("unset colorbox\n")

                # Set the bottom (left after rotation) margin so that score names are not truncated
                #
                outfile.write("set bmargin 10\n")
                outfile.write("set tmargin 5\n")
                outfile.write("set lmargin 8\n")
                outfile.write("set rmargin 5\n")

                # Produce multiple graphs side-by-side
                outfile.write("set multiplot layout 1, " + str(len(score_descriptions)) + "\n")

                # Set the graph style
                outfile.write("set style fill solid noborder\n")

                # Rotate the labels so that they are the expected rotation when the output is rotated
                #
                outfile.write("unset xtics\n")
                outfile.write("set ytics right rotate by 90\n")

                # Specify the X-axis parameters
                #
                outfile.write("set xrange [ 0.0 : 2.0 ]\n")
                outfile.write("set boxwidth 1.0\n")

                # Add a title to the scorecard
                #
                title = "Logistical budget for threat actor " + actor
                if start_date != epoch:
                    title += " starting at " + start_date.strftime("%Y-%m-%d")
                if end_date != epoch:
                    title += " ending at " + end_date.strftime("%Y-%m-%d")
                outfile.write("set label 1 \"" + title + "\" offset -7, 0 rotate by 90\n")

                # Set the palette for all scores: Gnuplot allows a single palette even in multiplots
                #
                outfile.write("set palette defined (")
                offset = 0.0
                numleft = len(scorecards[actor])
                for score in scorecards[actor]:
                    score_palette_offset[score] = offset
                    outfile.write(str(offset) + " \"grey\", ")
                    outfile.write(str(offset + (1.0 - 2.0 * score_fuzz[score])) + " \"grey\", ")
                    outfile.write(str(offset + (1.0 - score_fuzz[score])) + " \"" + score_colour[score] + "\", ")
                    outfile.write(str(offset + 1.0) + " \"white\"")
                    offset += 1.0
                    numleft -= 1
                    if numleft != 0:
                        outfile.write(", ")

                outfile.write(")\n")
                score_palette_max = offset
                outfile.write("set cbrange [ 0.0 : " + str(score_palette_max) + "]\n")

                # Now write out the data
                #
                for score in scorecards[actor]:
                    # Specify the Y-axis parameters
                    #
                    outfile.write("set ylabel \"" + score_units[score] + "\" offset 3, 0\n")
                    outfile.write("set yrange [ 0.0 : " + str(score_range[score]) + " ]\n")
                    if score_range[score] < 5.0:
                        outfile.write("set format y \"%1.1f\"\n")
                    else:
                        outfile.write("set format y \"%6.0f\"\n")

                    # Set the score description label
                    # TODO: Work out why rotate does not work in this case
                    outfile.write("set xlabel \"" + score_descriptions[score] + "\" offset 0, -2 rotate by 90\n")

                    # Output the scaled score
                    #
                    outfile.write("$" + score + " << EOD\n")
                    val = scorecards[actor][score]
                    if score_type[score] == "linear":
                        pass
                    elif score_type[score] == "log":
                        if val != 0:
                            val = math.log(val)
                    else:
                        raise RuntimeError("Unexpected score_type")
                    val = val * score_multiplier[score]
                    outfile.write("1 " + str(val / (1.0 - score_fuzz[score])) + "\n")
                    outfile.write("EOD\n")

                    # End the data, and plot
                    #
                    outfile.write("plot for [i=255:1:-1] \"$" + score + "\" using 1:(($2/256.0)*i):" +
                        "(" + str(score_palette_offset[score]) + "+(i/256.0)) notitle with boxes fillcolor palette\n")

                    outfile.write("unset label 1\n")

            # Process the plot into a temporary bitmap
            #
            try:
                process = subprocess.Popen(
                    args=["gnuplot", filename + ".plt"],
                    stdout=subprocess.PIPE)
                output = process.communicate()[0].decode("utf-8")
                if len(output) != 0:
                    print(output)
            except Exception as e:
                print("Unable to run gnuplot: Is it installed?  " + repr(e))

            # Rotate the bitmap output
            #
            try:
                process = subprocess.Popen(
                    args=["convert", "-rotate", "90", filename + ".tmp.png", filename + ".png"],
                    stdout=subprocess.PIPE)
                output = process.communicate()[0].decode("utf-8")
                if len(output) != 0:
                    print(output)
            except Exception as e:
                print("Unable to run convert: Is ImageMagick installed?  " + repr(e))

            # Remove the temporary output
            os.remove(filename + ".tmp.png");
