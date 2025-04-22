#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Guilhem Marchand"
__version__ = "0.1.0"
__status__ = "PRODUCTION"

import os
import sys
import time
import json
import logging
from logging.handlers import RotatingFileHandler
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ["SPLUNK_HOME"]

# set logging
filehandler = RotatingFileHandler(
    "%s/var/log/splunk/gsoctbox_checkcimquality.log" % splunkhome,
    mode="a",
    maxBytes=10000000,
    backupCount=1,
)
formatter = logging.Formatter(
    "%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s"
)
logging.Formatter.converter = time.gmtime
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


@Configuration()
class CheckCimQuality(StreamingCommand):

    cim_field_name = Option(
        doc="""
        **Syntax:** **cim_field_name=****
        **Description:** The name of the CIM field containing the list of values to check.""",
        require=False,
        default=None,
        validate=validators.Match("fields", r"^.*$"),
    )

    include_field_values = Option(
        doc="""
        **Syntax:** **include_field_values=****
        **Description:** Boolean option to include field values in the JSON summary.
        """,
        require=False,
        default=False,
        validate=validators.Boolean(),
    )

    # status will be statically defined as imported

    def stream(self, records):

        # set loglevel
        conf_file = "ta_gsoctbox_settings"
        confs = self.service.confs[str(conf_file)]
        for stanza in confs:
            if stanza.name == "logging":
                for stanzakey, stanzavalue in stanza.content.items():
                    if stanzakey == "loglevel":
                        loglevel = stanzavalue
        log.addHandler(filehandler)  # set the new handler
        # set the log level to INFO, DEBUG as the default is ERROR
        log.setLevel(logging.INFO)

        # Loop in the results
        for record in records:

            yield_record = {}
            json_summary = {}

            # Get the list of fields from cim_field_name
            if self.cim_field_name:
                fields_to_check = record.get(self.cim_field_name).split(",")
            else:
                fields_to_check = []

            # Initialize counters for summary
            total_fields_checked = 0
            total_fields_failed = 0

            # Check each field in the list
            for field in fields_to_check:
                field = field.strip()

                logging.info(f"Checking field: {field}")

                field_value = record.get(field)
                total_fields_checked += 1

                if field_value and field_value != "unknown":
                    # Mark as success if field exists, has a value, and is not 'unknown'
                    json_summary[field] = {
                        "status": "success",
                        "description": "Field exists and is valid.",
                    }
                    if self.include_field_values:
                        json_summary[field]["value"] = field_value
                else:
                    # Mark as failure with specific reason
                    if field_value is None or field_value == "":
                        reason = "is empty"
                    elif field_value == "unknown":
                        reason = "is 'unknown'"
                    else:
                        reason = "does not exist"
                    json_summary[field] = {
                        "status": "failure",
                        "description": f"Field {reason}.",
                    }
                    if self.include_field_values:
                        json_summary[field]["value"] = field_value
                    total_fields_failed += 1

            # Determine overall status
            overall_status = "success" if total_fields_failed == 0 else "failure"

            # Add summary to JSON
            json_summary["summary"] = {
                "overall_status": overall_status,
                "total_fields_checked": total_fields_checked,
                "total_fields_failed": total_fields_failed,
            }

            # Add the JSON summary to the yield_record
            yield_record["json_summary"] = json.dumps(json_summary, indent=4)

            # for each key value in record, add to yield_record
            for k, v in record.items():
                yield_record[k] = v

            yield yield_record


dispatch(CheckCimQuality, sys.argv, sys.stdin, sys.stdout, __name__)
