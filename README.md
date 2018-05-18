# LogisticalBudget
This project contains code for comparing or ranking APT capabilities and
operational capacity. The metrics are meant to quantify, rank, order,
compare, or visualise quickly threat actors demonstrated operational
capacities. In other words, it is meant to answer questions like 'Which
APT produces the most binaries yearly', or 'which apt uses the most
domains'.

# Dependencies

    pip3 install --user setuptools wheel
    pip3 install --user tqdm plotly pymisp

# Building and running

Copy settings.default.py to settings.py and edit it for the MISP server
and API key you are using.  Then run, for example:

    python3 generate.py
