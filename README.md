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

# Collaboration

LogisticalBudget is a collaborative effort between Concinnity Risks, Periapt Systems and xQ Enterprises Ltd.

![Periapt Systems logo](https://github.com/Concinnity-Risks/LogisticalBudget/blob/master/periapt-systems-logo-small.png)

![xQ Enterprises Ltd logo](https://github.com/Concinnity-Risks/LogisticalBudget/blob/master/xQ-sm-logo.png)
