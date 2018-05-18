#!/usr/bin/env python
# -*- coding: utf-8 -*-

# For progress bars
from tqdm import tqdm

# Modules directly associated with this application
#
import scoring
import utility


def threat_actor_scorecard(misp_data, actor):
    """
    Generate a score card for the specified threat actor

    misp_data - The events and attributes loaded from the MISP server
    actor - The threat actor to generate a score card for
    """

    events = misp_data["events"]
    attributes = misp_data["attributes"]

    # Initialise our scores for this threat actor
    #
    skill = 0
    team_size = 0
    resource_cost = 0
    time_cost = 0
    logistical_burden = 0

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

        if event_actor == actor:
            skill += scoring.score_skill(event, attributes)
            team_size += scoring.score_team_size(event, attributes)
            resource_cost += scoring.score_resource_cost(event, attributes)
            time_cost += scoring.score_time_cost(event, attributes)
            logistical_burden += scoring.score_logistical_burden(event, attributes)

    # Now generate our score card as a sumple text output for now
    #
    print("Score card for threat actor: " + actor)
    print("")
    print("Skill:              " + str(skill))
    print("Team size:          " + str(team_size))
    print("Resource cost:      " + str(resource_cost))
    print("Time cost:          " + str(time_cost))
    print("Logistical burden:  " + str(logistical_burden))
