#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Guilhem Marchand"
__version__ = "0.1.0"
__status__ = "PRODUCTION"

import os
import sys
import json
import logging
from logging.handlers import RotatingFileHandler
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ["SPLUNK_HOME"]

# set logging
filehandler = RotatingFileHandler(
    f"{splunkhome}/var/log/splunk/gsoctbox_prettyjson.log",
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
from splunklib import six
import splunklib.client as client


@Configuration()
class TrackMePrettyJson(StreamingCommand):

    fields = Option(
        doc="""
        **Syntax:** **fields=****
        **Description:** Comma Separated list of fields to pretty print.""",
        require=False,
        default="None",
        validate=validators.Match("fields", r"^.*$"),
    )

    # status will be statically defined as imported

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

        # convert the fields into a list
        fields_list = self.fields.split(",")

        # Loop in the results
        for record in records:

            yield_record = {}

            # loop through the fields, add to the dict record
            for k in record:

                if k in fields_list:
                    try:
                        yield_record[k] = json.dumps(json.loads(record[k]), indent=4)
                    except Exception as e:
                        logging.error(
                            f'Failed to load and render the json object in field="{k}"'
                        )
                        yield_record[k] = record[k]

                else:
                    yield_record[k] = record[k]

            yield yield_record


dispatch(TrackMePrettyJson, sys.argv, sys.stdin, sys.stdout, __name__)
