# LogisticalBudget
This project contains code for comparing or ranking APT capabilities and
operational capacity. The metrics are meant to quantify, rank, order,
compare, or visualise quickly threat actors demonstrated operational
capacities. In other words, it is meant to answer questions like 'Which
APT produces the most binaries yearly', or 'which APT uses the most
domains'.

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
