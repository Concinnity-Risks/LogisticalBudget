#!/usr/bin/env python
# -*- coding: utf-8 -*-


def score_by_event_count(event, attributes):
    """ Simple event counting score function """
    return 1


def score_by_event_threat_level(event, attributes):
    """ Score based on exponential of an event's threat level """
    score = 0

    if event["threat_level_id"] == "1":  # High
        score += 100
    elif event["threat_level_id"] == "2":  # Medium
        score += 50
    elif event["threat_level_id"] == "3":  # Low
        score += 1

    return score


def score_by_source_ips(event, attributes):
    """ Score based on number of source IPs implicated """
    score = 0

    for attribute in attributes:
        if attribute["category"] == "Network activity":
            ty = attribute["type"]
            if ty == "ip-src":
                score += 3

    return score


def score_by_destination_ips(event, attributes):
    """ Score based on number of destination IPs implicated """
    score = 0

    for attribute in attributes:
        if attribute["category"] == "Network activity":
            ty = attribute["type"]
            if ty == "ip-dst":
                score += 1

    return score


def score_by_domain_count(event, attributes):
    """ Score based on number of network artifacts implicated """
    score = 0

    for attribute in attributes:
        if attribute["category"] == "Network activity":
            ty = attribute["type"]
            if ty == "domain":
                score += 5

    return score

def score_by_malware_files(event, attributes):
    """ Score based on indicators of malware recorded """
    score = 0

    for attribute in attributes:
        if (attribute["category"] == "Payload installation") or (attribute["category"] == "Payload delivery"):
            ty = attribute["type"]
            if ty == "filename" or ty == "md5" or ty == "sha256" or ty == "sha1":
                score += 10

    return score


# Note: This scores nothing against threat actors
def score_by_amount_of_external_analysis(event, attributes):
    """ Score based on amount of external analysis recorded """
    score = 0

    for attribute in attributes:
        if attribute["category"] == "External analysis":
            ty = attribute["type"]
            if ty == "link count":
                score += 1
            elif ty == "comment count":
                score += 1

    return score


def score_team_size(event, attributes):
    """ Score based on indicators of team size """
    score = 0

    for attribute in attributes:
        if attribute["category"] == "Artifacts dropped":
            ty = attribute["type"]
            if ty == "vulnerability":
                score += 50
            elif ty == "malware-sample":
                score += 10
            elif ty == "filename" or ty == "filename|md5" or ty == "filename|sha1" or ty == "filename|sha256" or ty == "attachment":
                score += 5
        elif attribute["category"] == "Network activity":
            ty = attribute["type"]
            if ty == "domain":
                score += 20
        elif attribute["category"] == "Targeting data":
            ty = attribute["type"]
            if ty == "target-location":
                score += 50

    return score


def score_resource_cost(event, attributes):
    """ Score based on indicators of resource cost """
    score = 0

    for attribute in attributes:
        if attribute["category"] == "External analysis":
            ty = attribute["type"]
            if ty == "vulnerability":
                score += 50
            elif ty == "link count" or ty == "url count":
                score += 10
            elif ty == "comment count":
                score += 1

    return score


def score_time_cost(event, attributes):
    """ Score based on indicators of time cost """
    score = 0

    for attribute in attributes:
        if attribute["category"] == "External analysis":
            ty = attribute["type"]
            if ty == "vulnerability":
                score += 100
            elif ty == "link count" or ty == "url count":
                score += 10

    return score


def score_logistical_burden(event, attributes):
    """ Score based on indicators of logistical burden """

    team_size = score_team_size(event, attributes)
    resource_cost = score_resource_cost(event, attributes)
    time_cost = score_time_cost(event, attributes)

    return team_size * (resource_cost + time_cost)
