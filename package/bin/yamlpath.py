#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Guilhem Marchand"
__version__ = "0.1.0"
__status__ = "PRODUCTION"

import os
import sys
import logging
from logging.handlers import RotatingFileHandler
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ["SPLUNK_HOME"]

# set logging
filehandler = RotatingFileHandler(
    "%s/var/log/splunk/gsoctbox_yamlpath.log" % splunkhome,
    mode="a",
    maxBytes=10000000,
    backupCount=1,
)
formatter = logging.Formatter(
    "%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s"
)
filehandler.setFormatter(formatter)
log = logging.getLogger()  # root logger - Good to get it only once.
for hdlr in log.handlers[:]:  # remove the existing file handlers
    if isinstance(hdlr, logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)  # set the new handler
# set the log level to INFO, DEBUG as the default is ERROR
log.setLevel(logging.INFO)

sys.path.append(os.path.join(splunkhome, "etc", "apps", "TA-gsoctbox", "lib"))

# import Splunk libs
from splunklib.searchcommands import (
    dispatch,
    StreamingCommand,
    Configuration,
    Option,
    validators,
)

# import yaml from lib
import yaml


@Configuration(distributed=False)
class parseyamlCommand(StreamingCommand):

    def flatten_yaml(self, data, parent_key="", sep="."):
        """Recursively flattens a nested dictionary or list into a flat dictionary, storing lists as single fields."""
        items = {}
        if isinstance(data, dict):
            for k, v in data.items():
                new_key = (
                    f"{parent_key}{sep}{k.replace(' ', '_')}"
                    if parent_key
                    else k.replace(" ", "_")
                )
                items.update(self.flatten_yaml(v, new_key, sep=sep))
        elif isinstance(data, list):
            # Store the list as a single field
            items[parent_key] = data
        else:
            items[parent_key] = data
        return items

    def stream(self, records):

        # set loglevel
        loglevel = "INFO"
        conf_file = "ta_gsoctbox_settings"
        confs = self.service.confs[str(conf_file)]
        for stanza in confs:
            if stanza.name == "logging":
                for stanzakey, stanzavalue in stanza.content.items():
                    if stanzakey == "loglevel":
                        loglevel = stanzavalue
        log.setLevel(loglevel)

        logging.debug(f"starting yamlpath")

        # Loop in the results
        for record in records:

            yield_record = {}

            # Attempt to parse _raw as YAML
            try:
                yaml_content = yaml.safe_load(record["_raw"])
                flat_yaml = self.flatten_yaml(yaml_content)
                yield_record.update(flat_yaml)

            except Exception as e:
                log.error("Failed to parse YAML from _raw: {}".format(e))
                yield_record["_raw"] = record["_raw"]

            yield_record["_time"] = record.get("_time", time.time())
            yield_record["_raw"] = record["_raw"]

            yield yield_record

        # end
        logging.debug(f"yamlpath done")


dispatch(parseyamlCommand, sys.argv, sys.stdin, sys.stdout, __name__)
