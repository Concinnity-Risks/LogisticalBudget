#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2018 Éireann Leverett and Bruce Stenning
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


def score_by_event_count(event, attributes):
    """ Simple event counting score function """
    return 1


def score_by_event_threat_level(event, attributes):
    """ Score based on exponential of an event's threat level """
    score = 0

    if event["threat_level_id"] == "1":  # High
        score += 100
    elif event["threat_level_id"] == "2":  # Medium
        score += 10
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
                score += 1

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


def score_by_ip_count(event, attributes):
    """ Score based on number of IPs implicated """
    score = 0

    for attribute in attributes:
        if attribute["category"] == "Network activity":
            ty = attribute["type"]
            if ty == "ip-src" or ty == "ip-dst":
                score += 1

    return score


def score_by_domain_and_url(event, attributes):
    """ Score based on number of domains and urls implicated """
    score = 0

    for attribute in attributes:
        if attribute["category"] == "Network activity":
            ty = attribute["type"]
            if ty == "domain" or type == "url":
                score += 1

    return score


def score_by_malware_binaries(event, attributes):
    """ Score based on indicators of malware recorded """
    score = 0

    for attribute in attributes:
        if attribute["category"] == "Payload delivery":
            ty = attribute["type"]
            if ty == "filename" or ty == "md5" or ty == "sha256" or ty == "sha1":
                score += 1

    return score


# Note: This scores nothing against threat actors
def score_by_amount_of_external_analysis(event, attributes):
    """ Score based on amount of external analysis recorded """
    score = 0

    for attribute in attributes:
        if attribute["category"] == "External analysis":
            ty = attribute["type"]
            if ty == "link count":
                score += 5
            elif ty == "comment count":
                score += 1

    return score
