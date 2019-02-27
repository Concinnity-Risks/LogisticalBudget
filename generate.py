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
import datetime

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
import scorecards
import scatter
import utility


# A helper for parsing date arguments on the command-line
#
def validate_date(input_string):
    try:
        return datetime.datetime.strptime(input_string, "%Y-%m-%d")
    except ValueError:
        error = "Not a valid date: '{0}'.".format(input_string)
        raise argparse.ArgumentTypeError(error)

#
# Main program
#
if __name__ == "__main__":
    # Prepare a pretty printer for debug purposes
    pp = pprint.PrettyPrinter(indent=4)

    # Configure access to the MISP server.
    # Note that if the API key has not been configured, or has been incorrectly configured,
    # then this will throw a warning that authentication has failed, even if the --avoidserver
    # option has been specified so that just the cache is used.
    misp_server = PyMISP(url, key, ssl)

    # Process command-line arguments
    #
    epoch = datetime.datetime.utcfromtimestamp(0)

    parser = argparse.ArgumentParser(description="With no arguments, the cached data will be used to generate " +
        "heatmaps showing threat actors against time, scored by various criteria.")

    # Cache/server control options
    #
    parser.add_argument("--cachefile", metavar="FILENAME", dest="cache_filename", type=str, default="cache.obj",
         help="Set the name of the file that MISP data is cached to")

    parser.add_argument("--forcedownload", dest="force_download", action="store_const", const=True, default=False,
         help="Force download of all MISP data from the server rather than using the cache (this can be slow)")

    parser.add_argument("--avoidserver", dest="avoid_server", action="store_const", const=True, default=False,
         help="Avoid accessing the server, and solely use MISP data from the local cache")

    parser.add_argument("--dumpcache", dest="dump_cache", action="store_const", const=True, default=False,
         help="Load the contents of the cache and pretty-print it to a text file (named by default cache.txt).  " +
            "Implies --avoidserver")

    parser.add_argument("--dumpfile", metavar="FILENAME", dest="dump_filename", type=str, default="cache.txt",
         help="Specify the name of the file to output a dump of the cache to")

    # Options that help with analysis of available data
    #
    parser.add_argument("--listactors", dest="list_actors", action="store_const", const=True, default=False,
         help="Produce list of the known threat actors in the data")

    parser.add_argument("--analyse", dest="analyse", action="store_const", const=True, default=False,
         help="Produce an analysis of structure of the MISP data")

    # Options that select which outputs to generate
    #
    parser.add_argument("--heatmaps", dest="heatmaps", action="store_const", const=True, default=False,
         help="Generate heatmaps")

    parser.add_argument("--scorecards", dest="scorecards", action="store_const", const=True, default=False,
         help="Generate score cards")

    parser.add_argument("--scatter", dest="scatter_plots", action="store_const", const=True, default=False,
         help="Generate scatter plots")

    # Options that control how the heatmaps are generated
    #
    parser.add_argument("--numdays", metavar="DAYS", dest="num_days", type=int, default="0",
         help="Set the number of days of history for heatmaps")

    parser.add_argument("--binsize", metavar="DAYS", dest="bin_size", type=int, default="0",
         help="Set the number of days for each bin for heatmaps")

    # Options that control how the scorecards are generated
    #
    parser.add_argument("--startdate", metavar="DATE", dest="start_date", type=validate_date, default=epoch,
         help="Set the start date for threat actor scorecards, in the format YYYY-MM-DD")

    parser.add_argument("--enddate", metavar="DATE", dest="end_date", type=validate_date, default=epoch,
         help="Set the end date for threat actor scorecards, in the format YYYY-MM-DD")

    # Parse command-line arguments and then perform some extra validation
    #
    args = parser.parse_args()
    if args.num_days != 0 and args.bin_size == 0:
        print("When specifying the number of days, the bin size must be specified")
        sys.exit(1)
    if args.num_days == 0 and args.bin_size != 0:
        print("When specifying the bin size, the number of days must be specified")
        sys.exit(1)
    if args.bin_size != 0 and args.num_days % args.bin_size != 0:
        print("The number of days should be a multiple of the bin size to ensure that the")
        print("left hand side of the graph is not misleading")
        sys.exit(1)

    # Obtain the event data, either from the local cache or from the MISP server
    #
    misp_data = misp.get_misp_data(misp_server, args.cache_filename, args.force_download, args.avoid_server or args.dump_cache)
    total = len(misp_data["events"])
    if total == 0:
        sys.exit("No events returned")

    if args.dump_cache:
        # Pretty print the cache contents into a file
        caching.dump_cache(args.cache_filename, args.dump_filename)

    if args.analyse:
        # Perform some basic analysis on the MISP data, which can be useful
        # for learning what is present in the data
        analysis.analyse(misp_data)

    if args.list_actors:
        # List the threat actors present in the data
        #
        threat_actors = utility.identify_threat_actors(misp_data, initial={})
        for actor in threat_actors:
            print(actor)

    if args.scorecards:
        # Produce a score table against various criteria for each threat actor and for each ransomware
        #
        if not os.path.exists("scorecards-actors"):
            os.makedirs("scorecards-actors")
        print("Generating Threat Actor scorecards")
        scorecards.generate_threat_actor_scorecards(misp_data, "scorecards-actors", args.start_date, args.end_date)

        if not os.path.exists("scorecards-ransomware"):
            os.makedirs("scorecards-ransomware")
        print("Generating Ransomware scorecards")
        scorecards.generate_ransomware_scorecards(misp_data, "scorecards-ransomware", args.start_date, args.end_date)

    if args.scatter_plots:
        # Produce plot of activity of various threat actors over time
        #
        if not os.path.exists("scatter-plot-actors"):
            os.makedirs("scatter-plot-actors")
        print("Generating Threat Actor scatter plots")
        scatter.generate_threat_actor_scatter_plots(misp_data, "scatter-plot-actors", args.start_date, args.end_date)

        if not os.path.exists("scatter-plot-ransomware"):
            os.makedirs("scatter-plot-ransomware")
        print("Generating Ransomware scatter plots")
        scatter.generate_ransomware_scatter_plots(misp_data, "scatter-plot-ransomware", args.start_date, args.end_date)

    if args.heatmaps:
        # Generate the desired heat maps
        #
        if not os.path.exists("heatmaps"):
            os.makedirs("heatmaps")
        if args.num_days != 0 and args.bin_size != 0:
            print("Generating custom heatmaps")
            heatmaps.generate_heatmaps(misp_data, num_days = args.num_days, bin_size = args.bin_size, bin_name = "custom")
        else:
            print("Generating monthly heatmaps")
            heatmaps.generate_heatmaps(misp_data, num_days = 15 * 30, bin_size = 30, bin_name = "monthly")
            print("Generating weekly heatmaps")
            heatmaps.generate_heatmaps(misp_data, num_days = 3 * 30, bin_size = 7, bin_name = "weekly")
