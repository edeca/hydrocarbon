"""
A simple command line wrapper around the main feed generator object,
allowing hydrocarbon to be run directly as a tool.
"""

import argparse
import logging
from .core import FeedGenerator


def main():
    """
    Simple commandline wrapper around the main module.
    """

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(
        description=("Generate Carbon Black alliance feed from a "
                     "collection of YAML files")
    )
    parser.add_argument(
        "--data",
        type=str,
        help="directory containing YAML files (default: data/)",
        default="data",
    )
    parser.add_argument(
        "--config",
        type=str,
        help="configuration file (default: config.yaml)",
        default="config.yaml",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="output JSON file (default: output.json)",
        default="output.json",
    )
    parser.add_argument(
        "--icon-large",
        type=str,
        help="large icon, recommended 370x97 (optional)",
        default=None,
        required=False,
    )
    parser.add_argument(
        "--icon-small",
        type=str,
        help="small icon, recommended 100x100 (optional)",
        default=None,
        required=False,
    )
    parser.add_argument(
        "--git-enabled",
        help="enable git support (default: on)",
        default=True,
        action="store_true",
    )
    parser.add_argument(
        "--git-strict",
        help="error if files in git are untracked or modified (default: off)",
        default=False,
        action="store_true",
    )

    args = parser.parse_args()

    builder = FeedGenerator(
        args.config, use_git=args.git_enabled, git_strict=args.git_strict
    )

    if args.icon_large and args.icon_small:
        builder.add_icons(args.icon_large, args.icon_small)

    builder.add_data_dir(args.data)
    if builder.errors:
        for err in builder.errors:
            print("error: {}".format(err))
    else:
        with open(args.output, "w") as fh:
            builder.generate_feed(fh)


if __name__ == "__main__":
    main()
