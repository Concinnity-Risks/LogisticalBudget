#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Standard Python imports
#
import sys
import platform
import os
import json
import pprint
import argparse

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
import heatmaps
import actor
import utility


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
    parser = argparse.ArgumentParser(description="With no arguments, the cached data will be used to generate " +
        "heatmaps showing threat actors against time, scored by various criteria.")

    parser.add_argument("--nocache", dest="use_cache", action="store_const", const=False, default=True,
         help="Avoid reading or writing information from or to the cache and query the MISP server directly (which can be slow)")

    parser.add_argument("--dumpcache", dest="dump_cache", action="store_const", const=True, default=False,
         help="Load the contents of the cache.obj file and pretty-print it to a text file named cache.txt")

    parser.add_argument("--actorscores", dest="actor_scores", action="store_const", const=True, default=False,
         help="Show scoring for all threat actors")

    parser.add_argument("--listactors", dest="list_actors", action="store_const", const=True, default=False,
         help="Produce list of the known threat actors in the data")

    parser.add_argument("--analyse", dest="analyse", action="store_const", const=True, default=False,
         help="Produce an analysis of structure of the MISP data")

    args = parser.parse_args()

    # If requested, pretty print the cache contents into a file
    #
    if args.dump_cache:
        caching.dump_cache()
        sys.exit(0)

    # Obtain the event data, either from the local cache or from the MISP server
    #
    misp_data = misp.get_misp_data(misp_server, args.use_cache)
    total = len(misp_data["events"])
    if total == 0:
        sys.exit("No events returned")

    if args.actor_scores:
        # Produce a score table against various criteria for each threat actor
        #
        if not os.path.exists("scorecards"):
            os.makedirs("scorecards")
        scorecards.generate_threat_actor_scorecards(misp_data)

    elif args.analyse:
        # Perform some basic analysis on the MISP data, which can be useful
        # for learning what is present in the data
        analysis.analyse(misp_data)

    elif args.list_actors:
        # List the threat actors present in the data
        #
        threat_actors = utility.identify_threat_actors(misp_data, initial={})
        for actor in threat_actors:
            print(actor)

    else:
        # Generate the desired heat maps
        #
        if not os.path.exists("heatmaps"):
            os.makedirs("heatmaps")
        heatmaps.generate_heatmaps(misp_data)
