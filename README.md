# Introduction

This tool converts technical indicators (IOCs) and search queries into the
JSON format required for a Carbon Black alliance feed.  This can be imported
into your Carbon Black server manually or by adding a Threat Intelligence
feed, which will regularly update.

It was written by David Cannings ([@edeca](https://twitter.com/edeca)) and 
released by NCC Group under the AGPL.

The latest code can be found in the [Github repository](https://github.com/edeca/hydrocarbon).

# Why would I use it?

This tool is useful if:

* You want to synchronise watch lists across multiple Carbon Black servers.
* You want to share indicators (and you don't have a central threat intel platform).

# Quick start

To get started you will need:

* A configuration file (see `examples/config.yaml`)
* At least one data file (see `examples/data/`)

First install the tool in a virtual environment:

```
# Create a new virtual environment
$ python3 -m venv hydrocarbon_venv

# Activate the virtual environment
$ . hydrocarbon_venv/bin/activate  # On Windows run hydrocarbon_venv\Scripts\activate.ps1

# Instal the module
$ pip install hydrocarbon 
```

Now generate a JSON file with feed data:

```
# Generate JSON from the example data 
$ hydrocarbon --config examples\config.yaml --data examples\data --output feed.json
```

You can optionally provide two logos (100x100 and 370x97) to be included in
the feed data.  These wll be displayed in the web UI, for example:

```
# Generate JSON from the example data 
$ hydrocarbon --config examples\config.yaml --data examples\data --output feed.json \
              --icon-large examples\large.jpg --icon-small examples\small.jpg
```

INSERT IMAGE 

The tool can be used from within your own Python scripts, see the FAQ.

# FAQ

## Why integrate with git?

The Carbon Black server needs a timestamp for every report.  Using git gives 
an accurate timestamp (from the latest commit) which does not change.

It is possible to use without git.  However, this is not recommended for
anything other than testing.

## How can I delete indicators?

The Carbon Black Response server prefers to do an 'incremental' sync against 
feeds.  This means that deleted items will not be removed.

To delete an item change `enabled` to `False` and regenerate the feed.

## How can I automatically update my server?

Simply copy the JSON file to a web server which can be accessed by the Carbon
Black instance.  You can optionally use basic authentication and provide the
username and password in the Carbon Black web interface.

You can add a new feed to the Threat Intelligence section in Carbon Black.

There seem to be no restrictions on the web server other than returning valid
JSON.

## How can I integrate this with my workflow?

The tool is a Python module which can be imported and used from your own code.

```python
from hydrocarbon import FeedGenerator

builder = FeedGenerator("/path/to/config.yaml")
builder.add_data_dir("/path/to/data/")

with open("output.json", "w") as fh:
    builder.generate_feed(fh)
```

See `hydrocarbon/app.py` for an example implementation. 