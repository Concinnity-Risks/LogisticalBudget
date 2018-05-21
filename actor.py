#!/usr/bin/env python
# -*- coding: utf-8 -*-

# For progress bars
from tqdm import tqdm

# Modules directly associated with this application
#
import scoring
import utility


def generate_threat_actor_scorecards(misp_data):
    """
    Generate a score card for the specified threat actor

    misp_data - The events and attributes loaded from the MISP server
    """

    events = misp_data["events"]
    attributes = misp_data["attributes"]

    # Generate dictionary of threat actors
    threat_actors = utility.identify_threat_actors(misp_data, initial={})

    # Generate an initial collection of score cards
    #
    scorecards = {}
    for actor in threat_actors:
        scorecards[actor] = {
            "skill": 0,
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

        event_actor = "Unattributed"

        if "GalaxyCluster" in event:
            galaxycluster = event["GalaxyCluster"]
            for galaxy in galaxycluster:
                if "Galaxy" in galaxy:
                    if galaxy["type"] == "threat-actor":
                        event_actor = galaxy["value"]

        scorecards[actor]["skill"] += scoring.score_skill(event, attributes)
        scorecards[actor]["team_size"] += scoring.score_team_size(event, attributes)
        scorecards[actor]["resource_cost"] += scoring.score_resource_cost(event, attributes)
        scorecards[actor]["time_cost"] += scoring.score_time_cost(event, attributes)
        scorecards[actor]["logistical_burden"] += scoring.score_logistical_burden(event, attributes)

    # Now generate our score card as a sumple text output for now
    #
    for actor in threat_actors:
        print("Score card for threat actor: " + actor)
        print("")
        print("Skill:              " + str(scorecards[actor]["skill"]))
        print("Team size:          " + str(scorecards[actor]["team_size"]))
        print("Resource cost:      " + str(scorecards[actor]["resource_cost"]))
        print("Time cost:          " + str(scorecards[actor]["time_cost"]))
        print("Logistical burden:  " + str(scorecards[actor]["logistical_burden"]))
        print("")
