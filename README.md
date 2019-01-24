# LogisticalBudget
This project contains code for comparing or ranking APT capabilities and
operational capacity. The metrics are meant to quantify, rank, order,
compare, or visualise quickly threat actors demonstrated operational
capacities. In other words, it is meant to answer questions like 'Which
APT produces the most binaries yearly', or 'which APT uses the most
domains'.

For example, over all indicators, which groups have been the most active?

![Heatmap analysis of a few APTs](https://github.com/Concinnity-Risks/LogisticalBudget/blob/master/heatmap-analysis-monthly.png)

Or if we examine a specific group, can we make comparisons between how big they are or how much they spend based on IoCs?

![APT specific scorecard for darkhotel](https://github.com/Concinnity-Risks/LogisticalBudget/blob/master/scorecard-darkhotel.png)

For Ransomware, can we estimate how much development time is involved, or how many people participate by comparison to other ransomware groups?

![APT specific scorecard for Wannacry](https://github.com/Concinnity-Risks/LogisticalBudget/blob/master/scorecard-WannaCry.png)

These estimates are not likely to be accurate in any absolute value sense, but they do allow analysis of attributed events in your MISP instance, which can be remarkably useful for some kinds of strategic work. For example, budgeting defenses or increased RE time against certain APTs.

# Dependencies

Install Python packages:

    pip3 install --user setuptools wheel
    pip3 install --user tqdm plotly pymisp

Install additional packages, for example on Red Hat based systems:

    sudo dnf install gnuplot ImageMagick

Alternatively, on Debian based systems:

    sudo apt-get install gnuplot graphicsmagick

## For Mac OS users

Install Python packages:
1.  ``` $ pip3 install --user setuptools wheel ```
2.  ``` $ pip3 install --user tqdm plotly pymisp ```

It might be necessary to update the PATH variables in your bash profile.

To install the additional packages install Homebrew if you do not already have it: https://brew.sh/ then run the following commands in Terminal.

1.  ``` $ brew install gnuplot ```
2.  ``` $ brew install imagemagick ```
3.  ``` $ brew install graphicsmagick ```


# Building and running

Copy settings.default.py to settings.py and edit it for the MISP server
and API key you are using.  Then run, for example:

    python3 generate.py

# Caching of MISP data

The MISP data is cached locally because it can take upwards of an hour to
fetch all of the attribute data from the MISP server.

The MISP event data will always be downloaded from the MISP server as this is
a relatively quick operation.

By default, attribute data associated with an event will only be downloaded
from the server where the event data just downloaded differs from the event
data in the cache.  To force a full download of all attribute data, use the
``` --forcedownload ``` command-line option.

# Collaboration

LogisticalBudget is a collaborative effort between Concinnity Risks and Periapt Systems.

![Periapt Systems logo](https://github.com/Concinnity-Risks/LogisticalBudget/blob/master/periapt-systems-logo-small.png)
