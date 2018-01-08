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


# Standard Python imports
#
import sys
import platform
import os
import json
import pprint

# Use local Python modules if requested
#
if "--local" in sys.argv:
    if platform.system() == "Windows":
        sys.path.insert(0, "D:\\keep\\packages\\git\\PyMISP")
    else:
        sys.path.insert(0, "~/keep/packages/git/PyMISP")

# Access to MISP servers
from pymisp import PyMISP

# Private settings for access to the chosen MISP server
from settings import url, key, ssl

# Modules directly associated with this application
#
import caching
import misp
import analysis
import scoring
import heatmaps


#
# Main program
#
if __name__ == "__main__":
    # Prepare a pretty printer for debug purposes
    pp = pprint.PrettyPrinter(indent=4)

    # Configure access to the MISP server
    misp_server = PyMISP(url, key, ssl)

    # Process command-line arguments
    #
    dump_cache = False
    use_cache = True
    analyse = False
    for arg in sys.argv[1:]:
        if arg == "--dumpcache":
            dump_cache = True
        elif arg == "--nocache":
            use_cache = False
        elif arg == "--analyse":
            analyse = True
        else:
            print("Unknown command-line argument: " + arg)
            print("Known arguments: --dumpcache --nocache --analyse")
            sys.exit(1)

    # If requested, pretty print the cache contents into a file
    #
    if dump_cache:
        caching.dump_cache()
        sys.exit(0)

    # Obtain the event data, either from the local cache or from the MISP server
    #
    misp_data = misp.get_misp_data(misp_server, use_cache)
    total = len(misp_data["events"])
    if total == 0:
        sys.exit("No events returned")

    if analyse:
        # Perform some basic analysis on the MISP data, which can be useful
        # for learning what is present in the data
        #
        analysis.analyse(misp_data)
    else:
        # Generate the desired heat maps
        #

        sets = []
        for html in [True, False]:
            for monthly in [False, True]:
                sets.append(
                    {"num_days": 15 * 30 if monthly else 3 * 30,
                     "bin_size": 30 if monthly else 7,
                     "scoring_function": scoring.score_by_event_count,
                     "scoring_name": "Threat actor events",
                     "filename": "heatmap-count-" + ("monthly" if monthly else "weekly"),
                     "use_plotly": html
                     })
                sets.append(
                    {"num_days": 15 * 30 if monthly else 3 * 30,
                     "bin_size": 30 if monthly else 7,
                     "scoring_function": scoring.score_by_event_threat_level,
                     "scoring_name": "Sum of event threat levels (high = 100, medium = 10, low = 1)",
                     "filename": "heatmap-levels-" + ("monthly" if monthly else "weekly"),
                     "use_plotly": html
                     })
                sets.append(
                    {"num_days": 15 * 30 if monthly else 3 * 30,
                     "bin_size": 30 if monthly else 7,
                     "scoring_function": scoring.score_by_source_ips,
                     "scoring_name": "Number of source IP addresses implicated",
                     "filename": "heatmap-ipsrc-" + ("monthly" if monthly else "weekly"),
                     "use_plotly": html
                     })
                sets.append(
                    {"num_days": 15 * 30 if monthly else 3 * 30,
                     "bin_size": 30 if monthly else 7,
                     "scoring_function": scoring.score_by_destination_ips,
                     "scoring_name": "Number of destination IP addresses implicated",
                     "filename": "heatmap-ipdst-" + ("monthly" if monthly else "weekly"),
                     "use_plotly": html
                     })
                sets.append(
                    {"num_days": 15 * 30 if monthly else 3 * 30,
                     "bin_size": 30 if monthly else 7,
                     "scoring_function": scoring.score_by_ip_count,
                     "scoring_name": "Number of IP addresses implicated",
                     "filename": "heatmap-ipcount-" + ("monthly" if monthly else "weekly"),
                     "use_plotly": html
                     })
                sets.append(
                    {"num_days": 15 * 30 if monthly else 3 * 30,
                     "bin_size": 30 if monthly else 7,
                     "scoring_function": scoring.score_by_domain_and_url,
                     "scoring_name": "Number of domains and URLs implicated",
                     "filename": "heatmap-domainsandurls-" + ("monthly" if monthly else "weekly"),
                     "use_plotly": html
                     })
                sets.append(
                    {"num_days": 15 * 30 if monthly else 3 * 30,
                     "bin_size": 30 if monthly else 7,
                     "scoring_function": scoring.score_by_malware_binaries,
                     "scoring_name": "Numbers of malware binaries recorded",
                     "filename": "heatmap-binaries-" + ("monthly" if monthly else "weekly"),
                     "use_plotly": html
                     })
                # This scores nothing against threat actors
                # sets.append(
                #     {"num_days": 15 * 30 if monthly else 3 * 30,
                #      "bin_size": 30 if monthly else 7,
                #      "scoring_function": scoring.score_by_amount_of_external_analysis,
                #      "scoring_name": "Numbers of amount of external analysis recorded",
                #      "filename": "heatmap-analysis-" + ("monthly" if monthly else "weekly"),
                #      "use_plotly": html
                #      })

        for set in sets:
            heatmaps.generate_by_threat_actor(
                misp_data, **set)
