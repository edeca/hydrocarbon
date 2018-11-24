"""
hydrocarbon is a simple Python class to help you build a Carbon Black
feed from structured data.  It is useful for use in small deployments
where a full threat intelligence platform is impractical.  For example, it
can be used to supply the Carbon Black platform with indicators specific
to your organisation, complementing public feeds.

Input data is structured YAML which closely matches the required format.
Technical indicators are validated to avoid pushing broken data to the
CB platform.

The module is designed to be used with data from a git repository, which
provides useful tracking of modification times.  However, if git is not
available then filesystem modification times will be used instead.

The resulting JSON can be hosted on any webserver (preferably with
authentication enabled) to serve the
"""

import base64
import re
import ipaddress
import json
import hashlib
import urllib.parse
from io import BytesIO
from pathlib import Path
from os.path import getmtime
from git import Repo
from git.exc import InvalidGitRepositoryError
from PIL import Image
import yaml

# TODO: Move to logging instead of print


class FeedGenerator:
    """
    The main HydroCarbon class, used to parse data and write the JSON to a
    filehandle.

    Use like:

        from hydrocarbon import FeedGenerator
        builder = FeedGenerator('config.yaml')
        builder.add_data_dir('/path/to/git/repo')
        with open('output.json', 'w') as fh:
            builder.generate_feed(fh)

        if builder.errors:
            print('Found errors')
            for err in builder.errors:
                # .. err is a string ..
    """

    _config = None
    _data_dirs = []
    _git_enabled = False
    _git_strict = False
    _icon_small = None
    _icon_large = None
    _repo = None
    errors = []

    def __init__(self, config_file, use_git=True, git_strict=False):
        """
        Minimum required initialisation.
        """
        self._init_regex()
        self._load_config(config_file)
        self._git_enabled = use_git
        self._git_strict = git_strict

    def add_data_dir(self, data_dir):
        """
        Add a directory full of YAML files to process.  Ideally this will be
        a git repository (or a subdirectory of a git repository).
        """

        try:
            self._data_dirs.append(Path(data_dir).absolute().resolve())

        except FileNotFoundError:
            self.errors.append("Cannot find data dir {}".format(data_dir))
            return False

        return True

    @staticmethod
    def _convert_image(filename, optimum_width=0, optimum_height=0):
        with Image.open(filename) as img:
            width, height = img.size

            if optimum_width and width != optimum_width:
                # TODO: log an error
                print(
                    "Width of image {} does not match recommended {}".format(
                        filename, optimum_width
                    )
                )

            if optimum_height and height != optimum_height:
                # TODO: log an error
                print(
                    "Height of image {} does not match recommended {}".format(
                        filename, optimum_height
                    )
                )

            output = BytesIO()
            img.save(output, format="PNG")
            return base64.b64encode(output.getvalue()).decode("ascii")

    def add_icons(self, icon_large_fn, icon_small_fn):
        """
        Add the "small" and "large" icons from file.  Validates they are
        images and warns if dimensions do not match the ideal size.
        """
        self._icon_large = self._convert_image(icon_large_fn, 370, 97)
        self._icon_small = self._convert_image(icon_small_fn, 100, 100)

    def _load_config(self, config_fn):
        """
        Load the configuration file, which contains feed specific information.
        """

        try:
            with open(config_fn, "r") as fh:
                self._config = yaml.load(fh)
        except FileNotFoundError:
            self.errors.append("Configuration file {} not found!".format(config_fn))

    @staticmethod
    def _get_git_repo(repo_dir):
        """
        Check that a git repository can be correctly parsed.
        """
        try:
            repo = Repo(repo_dir, search_parent_directories=True)
        except InvalidGitRepositoryError:
            print("can't open path as a git repo: {}".format(repo_dir))
            return None

        return repo

    def _init_regex(self):
        """
        Precompile frequently used regular expressions for speed.
        """
        self._regex_md5 = re.compile(r"[0-9a-f]{32}", re.IGNORECASE)
        self._regex_dns = re.compile(
            r"((xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}", re.IGNORECASE
        )

    def _validate_md5(self, value):
        """
        Validates an MD5 hash using regular expressions.  Returns the
        lower case version of the hash.
        """

        if not self._regex_md5.match(value):
            # TODO: Log an error
            return None

        return value.lower()

    def _validate_ipv4(self, value):  # pylint: disable=no-self-use
        """
        Validates an IP address using ipaddress module.  Needs Python 3.3+ or
        compatible Python 2 module.
        """
        try:
            ipaddress.ip_address(value)
        except ValueError:
            # TODO: Log an error
            return None

        return value

    def _validate_ipv6(self, value):
        """
        Validate IPv6 address, uses the same mechanism as IPv4.
        """
        return self._validate_ipv4(value)

    def _validate_dns(self, value):
        """
        Validate a domain name using regular expression.  Returns the
        lower case version of the domain.
        """
        if not self._regex_dns.match(value):
            # TODO: Log an error
            return None

        return value.lower()

    @staticmethod
    def _copy_keys(source, dest, keys, required=True):
        """
        Copy a set of keys from one dictionary to another.  If the required
        parameter is True then all keys _must_ exist in the source dict, or
        the function will return False.
        """
        try:
            for key in keys:
                dest[key] = source[key]
        except KeyError:
            if required:
                print("warning: required field {} is missing".format(key))
                return False

        return True

    @staticmethod
    def _extract_tags(report):

        out = []

        try:
            tags = report["meta"]["tags"]
        except KeyError:
            return None

        # Validate it's an array
        if not isinstance(tags, (list,)):
            print("Error: tags should be a list")
            return None

        for tag in tags:
            if not tag.isalnum():
                print("Error: tag is not alphanumeric!")
                continue

            if len(tag) > 32:
                print("Error: tag is too long!")
                continue

            out.append(tag)

        return out

    def _get_modification_time(self, filename, repo):
        """
        Get the modification time of a report from git (if supported), or
        from the local filesystem.
        """

        if self._git_enabled and repo:
            relative_name = str(filename.relative_to(repo.working_dir))

            # Get a list of changed files
            changed = [item.a_path for item in repo.index.diff(None)]

            # Check if this file is dirty or untracked
            if relative_name in repo.untracked_files or relative_name in changed:
                print(
                    "warning: file is untracked or modified: {}".format(relative_name)
                )
                if self._git_strict:
                    self.errors.append(
                        "Untracked or modified file: {}".format(relative_name)
                    )

            else:
                commit = next(repo.iter_commits(paths=relative_name))
                return commit.committed_date

        return int(getmtime(str(filename)))

    @staticmethod
    def _create_unique_id(filename, current_dir):
        """
        Create a unique path from
        """
        relative_name = filename.relative_to(current_dir)
        return hashlib.sha256(str(relative_name).encode("utf-8")).hexdigest()

    def _extract_indicators(self, iocs, report):
        """
        Extract indicators for a single report, checking them using inbuilt
        validation functions.
        """

        indicators = 0
        valid_keys = ["md5", "ipv4", "ipv6", "dns"]

        for key, data in iocs.items():
            if key not in valid_keys:
                # TODO: Log an error
                continue

            report["iocs"][key] = set()

            validator = getattr(self, "_validate_{}".format(key))

            for item in data:
                validated = validator(item)

                if validated:
                    # TODO: Unique the indicators here (consider using a set)
                    indicators += 1
                    report["iocs"][key].add(validated)
                else:
                    print("Couldn't validate indicator {} as {}".format(item, key))

        return indicators

    @staticmethod
    def _extract_query(query, report):

        qry = {}
        valid_types = ["events", "modules"]

        try:
            if query["type"] in valid_types:
                qry["index_type"] = query["type"]
            else:
                # TODO: Log an error
                return 0

            # TODO: Check it doesn't start q=
            search = query["search"]

            if search.startswith("q="):
                print(("Warning: search query starts with q=, this "
                       "is not necessary and should be removed"))
                search = search[2:]

            qry["search_query"] = "q={}".format(urllib.parse.quote(search))

        except KeyError:
            print("Error: did not find required query data, please see the template")
            return 0

        report["iocs"]["query"] = [qry]
        return 1

    def _parse_file(self, filename, current_dir, repo=None):
        """
        Parse a single data file and return the corresponding report
        structure, or None if parsing fails.
        """
        report = {'iocs': {}}
        indicators = 0
        queries = 0

        with open(str(filename), "r") as fh:
            data = yaml.load(fh)

        # TODO: Check it has the basic keys
        if not "meta" in data:
            print("error: meta section is missing")
            return None

        if not ("query" in data or "iocs" in data):
            print("error: data does not contain a query or iocs")
            return None

        required_fields = ["link", "title", "score"]
        if not self._copy_keys(data["meta"], report, required_fields, True):
            return None

        tags = self._extract_tags(data)
        if tags:
            report["tags"] = tags

        # Unique ID is the SHA256 of filename.  Filenames can contain
        # non-ASCII bytes, spaces, etc.
        report["id"] = self._create_unique_id(filename, current_dir)

        # Get the timestamp, either from git (preferred) or filesystem
        report["timestamp"] = self._get_modification_time(filename, repo)

        # To enable deletion of reports we need to generate an item with
        # an updated timestamp but no indicators.
        if not data["meta"].get("enabled", True):
            return report

        if "iocs" in data:
            indicators = self._extract_indicators(data["iocs"], report)

        if "query" in data:
            if indicators:
                print(
                    "Error: this report already has IOCs, cannot also have a search query"
                )
            else:
                queries = self._extract_query(data["query"], report)

        if indicators or queries:
            print("extracted {} indicators and {} queries".format(indicators, queries))
            return report

        print("didn't extract any indicators from file {}".format(filename))
        return None

    def generate_feed(self, output_fh):
        """
        Generate the feed, returning the output in output_fh.  This can
        be a file, memory stream or any other valid handle.
        """

        output = {}
        output["feedinfo"] = {}
        output["reports"] = []

        # Generate feedinfo (metadata about this feed)
        required_fields = [
            "name",
            "display_name",
            "provider_url",
            "summary",
            "tech_data",
        ]

        if not self._copy_keys(self._config, output["feedinfo"], required_fields, True):
            return False

        if self._icon_large:
            output["feedinfo"]["icon"] = self._icon_large
        if self._icon_small:
            output["feedinfo"]["icon_small"] = self._icon_small

        for directory in self._data_dirs:
            self._process_directory(directory, output)

        output_fh.write(json.dumps(output))
        return True

    def _process_directory(self, data_dir, output):

        repo = self._get_git_repo(data_dir)

        # Read each file and generate a report
        files = Path(data_dir).glob("**/*.yaml")

        for fn in files:
            print("reading file: {}".format(fn))
            report = self._parse_file(fn, data_dir, repo)
            if report:
                output["reports"].append(report)
