#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Standard Python imports
#
import os
import subprocess

# For progress bars
from tqdm import tqdm

# Modules directly associated with this application
#
import scoring
import utility


# TODO: Title for the scorecard
# TODO: More representative scoring functions
# TODO: Error bars (or similar)


def generate_threat_actor_scorecards(misp_data):
    """
    Generate a score card for the specified threat actor

    misp_data - The events and attributes loaded from the MISP server
    """

    events = misp_data["events"]
    attributes = misp_data["attributes"]

    # Generate dictionary of threat actors
    threat_actors = utility.identify_threat_actors(misp_data, initial={})

    # Set up the score characteristics
    #
    score_descriptions = {
        "team_size": "Team Size",
        "resource_cost": "Resource Cost",
        "time_cost": "Time Cost",
        "logistical_burden": "Logistical Burden"
    };

    score_units = {
        "team_size": "People",
        "resource_cost": "$",
        "time_cost": "Years",
        "logistical_burden": ""
    };

    score_range = {
        "team_size": 30,
        "resource_cost": 1000000,
        "time_cost": 3,
        "logistical_burden": 1000
    };

    # Unlike the heatmap scores, which are used for comparative analysis of the threat actors, this
    # is a bit more complex in that the scores are intended to be absolutes in specific units.
    #
    score_multiplier = {
        "team_size": 0.00001,
        "resource_cost": 2000,
        "time_cost": 0.002,
        "logistical_burden": 0.00002
    };

    # Generate an initial collection of score cards
    #
    scorecards = {}
    for actor in threat_actors:
        scorecards[actor] = {
            "team_size": 0,
            "resource_cost": 0,
            "time_cost": 0,
            "logistical_burden": 0
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
            scorecards[event_actor]["team_size"] += scoring.score_team_size(event, event_attributes)
            scorecards[event_actor]["resource_cost"] += scoring.score_resource_cost(event, event_attributes)
            scorecards[event_actor]["time_cost"] += scoring.score_time_cost(event, event_attributes)
            scorecards[event_actor]["logistical_burden"] += scoring.score_logistical_burden(event, event_attributes)

    # Now generate our score card as a sumple text output for now
    #
    for actor in threat_actors:
        print("Score card for threat actor: " + actor)
        print("")
        print("Team size:          " + str(scorecards[actor]["team_size"]))
        print("Resource cost:      " + str(scorecards[actor]["resource_cost"]))
        print("Time cost:          " + str(scorecards[actor]["time_cost"]))
        print("Logistical burden:  " + str(scorecards[actor]["logistical_burden"]))
        print("")

    # Generate a chart for each threat actor
    #
    if not threat_actors:
        print("No threat actors")
    else:
        height = len(threat_actors)

        for actor in threat_actors:
            filename = "scorecard-" + actor
            with open(filename + ".plt", "w") as outfile:
                # Set the size of the output image (though note that it will be rotated)
                outfile.write("set terminal png size 720, 1280\n")

                # Set the filename of the output image
                outfile.write("set output \"" + filename + ".tmp.png\"\n")

                # Don't draw a key
                outfile.write("unset key\n")

                # Set the bottom (left after rotation) margin so that score names are not truncated
                #
                outfile.write("set bmargin 10\n")
                outfile.write("set tmargin 5\n")
                outfile.write("set lmargin 5\n")
                outfile.write("set rmargin 5\n")

                # Produce multiple graphs side-by-side
                #
                outfile.write("set multiplot layout 1, " + str(len(score_descriptions)) + "\n")

                # Titling is tricky with multiplot: Adding a title to a single graph scales that graph differently
                # outfile.write("set title \"Logistical burden for threat actor " + actor + "\"\n")

                # Set the histogram style
                #
                outfile.write("set style histogram columns\n")
                outfile.write("set style fill solid\n")

                # Now write out the data
                #
                for score in scorecards[actor]:
                    # Rotate the labels so that they are the expected rotation when the output is rotated
                    outfile.write("set xtics right rotate by 90\n")

                    # Specify the Y-axis parameters
                    #
                    outfile.write("set ytics right rotate by 90\n")
                    outfile.write("set ylabel \"" + score_units[score] + "\" offset 3, 0\n")
                    outfile.write("set yrange [ 0.0 : " + str(score_range[score]) + " ]\n")
                    if score_range[score] < 5.0:
                        outfile.write("set format y \"%1.1f\"\n")
                    else:
                        outfile.write("set format y \"%6.0f\"\n")

                    # Output the scaled score
                    #
                    outfile.write("$" + score + " << EOD\n\"\" 0\n")
                    val = scorecards[actor][score] * score_multiplier[score]
                    outfile.write("\"" + str(score_descriptions[score]) + "\" " + str(val) + "\n")

                    # End the data, and plot
                    #
                    outfile.write("EOD\n")
                    outfile.write("plot \"$" + score + "\" using 2:xtic(1) ti col with histograms\n")

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
