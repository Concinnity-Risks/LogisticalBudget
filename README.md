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

These estimates are not likely to accurate, but they do allow analysis of attributed events in your MISP instance, which can be remarkably useful for some kinds of strategic work.

# Dependencies

Install Python packages:

    pip3 install --user setuptools wheel
    pip3 install --user tqdm plotly pymisp

Install additional packages, for example on Red Hat based systems:

    sudo dnf install gnuplot ImageMagick

Alternatively, on Debian based systems:

    sudo apt-get install gnuplot graphicsmagick

# Building and running

Copy settings.default.py to settings.py and edit it for the MISP server
and API key you are using.  Then run, for example:

    python3 generate.py
