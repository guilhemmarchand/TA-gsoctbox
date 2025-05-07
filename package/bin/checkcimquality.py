#!/usr/bin/env python
# coding=utf-8

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

# append lib
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

    fields_to_check_list = Option(
        doc="""
        **Syntax:** **fields_to_check_list=****
        **Description:** The list of fields to verified, provided as an argument to the command in a comma separated list.""",
        require=False,
        default=None,
        validate=validators.Match("fields_to_check_list", r"^.*$"),
    )

    fields_to_check_fieldname = Option(
        doc="""
        **Syntax:** **fields_to_check_fieldname=****
        **Description:** Alternatively, the name of the field containing the list of fields to check, provided in a comma separated list.""",
        require=False,
        default=None,
        validate=validators.Match("fields_to_check_fieldname", r"^.*$"),
    )

    fields_to_check_dict = Option(
        doc="""
        **Syntax:** **fields_to_check_dict=****
        **Description:** A JSON string containing a dictionary of fields to check with optional regex patterns.
        Example: {"field1": {"name": "field1", "regex": "^[A-Z]+$"}, "field2": {"name": "field2"}}""",
        require=False,
        default=None,
        validate=validators.Match("fields_to_check_dict", r"^.*$"),
    )

    fields_to_check_dict_path = Option(
        doc="""
        **Syntax:** **fields_to_check_dict_path=****
        **Description:** Path to a JSON file containing a dictionary of fields to check with optional regex patterns.
        Example: $SPLUNK_HOME/etc/apps/trackme/lookups/fields_config.json""",
        require=False,
        default=None,
        validate=validators.Match("fields_to_check_dict_path", r"^.*$"),
    )

    fields_to_check_dict_fieldname = Option(
        doc="""
        **Syntax:** **fields_to_check_dict_fieldname=****
        **Description:** The name of the field containing a JSON string with a dictionary of fields to check with optional regex patterns.
        """,
        require=False,
        default=None,
        validate=validators.Match("fields_to_check_dict_fieldname", r"^.*$"),
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

    pretty_print_json = Option(
        doc="""
        **Syntax:** **pretty_print_json=****
        **Description:** Boolean option to pretty print the JSON summary. Default is True.
        """,
        require=False,
        default=True,
        validate=validators.Boolean(),
    )

    # status will be statically defined as imported

    def stream(self, records):

        # Start performance counter
        start = time.time()

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

        # either fields_to_check_list or fields_to_check_fieldname must be provided, but not both
        if (
            sum(
                1
                for x in [
                    self.fields_to_check_list,
                    self.fields_to_check_fieldname,
                    self.fields_to_check_dict,
                    self.fields_to_check_dict_path,
                    self.fields_to_check_dict_fieldname,
                ]
                if x
            )
            > 1
        ):
            raise ValueError(
                "Only one of fields_to_check_list, fields_to_check_fieldname, fields_to_check_dict, fields_to_check_dict_path, or fields_to_check_dict_fieldname can be provided"
            )

        # Loop in the results
        records_count = 0
        for record in records:
            records_count += 1

            yield_record = {}
            json_summary = {}

            # Get the list of fields from fields_to_check_list
            if self.fields_to_check_list:
                fields_to_check = self.fields_to_check_list.split(",")
                fields_dict = {
                    field.strip(): {"name": field.strip()} for field in fields_to_check
                }

            # Get the list of fields from fields_to_check_fieldname
            elif self.fields_to_check_fieldname:
                fields_to_check = record.get(self.fields_to_check_fieldname).split(",")
                fields_dict = {
                    field.strip(): {"name": field.strip()} for field in fields_to_check
                }

            # Get fields from fields_to_check_dict
            elif self.fields_to_check_dict:
                try:
                    fields_dict = json.loads(self.fields_to_check_dict)
                    # Validate the structure
                    for field_name, field_info in fields_dict.items():
                        if not isinstance(field_info, dict):
                            raise ValueError(f"Field {field_name} must be a dictionary")
                        if "name" not in field_info:
                            raise ValueError(
                                f"Field {field_name} must have a 'name' property"
                            )
                        if not isinstance(field_info["name"], str):
                            raise ValueError(
                                f"Field {field_name} name must be a string"
                            )
                        if "regex" in field_info and not isinstance(
                            field_info["regex"], str
                        ):
                            raise ValueError(
                                f"Field {field_name} regex must be a string if provided"
                            )
                except json.JSONDecodeError:
                    raise ValueError("Invalid JSON format in fields_to_check_dict")

            # Get fields from fields_to_check_dict_path
            elif self.fields_to_check_dict_path:
                try:
                    # Handle relative paths from SPLUNK_HOME
                    if not os.path.isabs(self.fields_to_check_dict_path):
                        file_path = os.path.join(
                            splunkhome, self.fields_to_check_dict_path
                        )
                    else:
                        file_path = self.fields_to_check_dict_path

                    if not os.path.exists(file_path):
                        raise ValueError(f"JSON file not found: {file_path}")

                    with open(file_path, "r") as f:
                        fields_dict = json.load(f)

                    # Validate the structure
                    for field_name, field_info in fields_dict.items():
                        if not isinstance(field_info, dict):
                            raise ValueError(f"Field {field_name} must be a dictionary")
                        if "name" not in field_info:
                            raise ValueError(
                                f"Field {field_name} must have a 'name' property"
                            )
                        if not isinstance(field_info["name"], str):
                            raise ValueError(
                                f"Field {field_name} name must be a string"
                            )
                        if "regex" in field_info and not isinstance(
                            field_info["regex"], str
                        ):
                            raise ValueError(
                                f"Field {field_name} regex must be a string if provided"
                            )
                except json.JSONDecodeError:
                    raise ValueError(
                        f"Invalid JSON format in file: {self.fields_to_check_dict_path}"
                    )
                except IOError as e:
                    raise ValueError(f"Error reading JSON file: {str(e)}")

            # Get fields from fields_to_check_dict_fieldname
            elif self.fields_to_check_dict_fieldname:
                try:
                    json_string = record.get(self.fields_to_check_dict_fieldname)
                    fields_dict = json.loads(json_string)
                    # Validate the structure
                    for field_name, field_info in fields_dict.items():
                        if not isinstance(field_info, dict):
                            raise ValueError(f"Field {field_name} must be a dictionary")
                        if "name" not in field_info:
                            raise ValueError(
                                f"Field {field_name} must have a 'name' property"
                            )
                        if not isinstance(field_info["name"], str):
                            raise ValueError(
                                f"Field {field_name} name must be a string"
                            )
                        if "regex" in field_info and not isinstance(
                            field_info["regex"], str
                        ):
                            raise ValueError(
                                f"Field {field_name} regex must be a string if provided"
                            )
                except json.JSONDecodeError:
                    raise ValueError(
                        "Invalid JSON format in fields_to_check_dict_fieldname"
                    )

            else:
                fields_dict = {}

            # Initialize counters for summary
            total_fields_checked = 0
            total_fields_failed = 0
            total_fields_passed = 0

            # Check each field in the dictionary
            for field_info in fields_dict.values():
                field = field_info["name"]
                regex_pattern = field_info.get("regex")

                logging.info(f"Checking field: {field}")

                field_value = record.get(field)
                total_fields_checked += 1

                if field_value and field_value.lower() != "unknown":
                    # Check regex pattern if specified
                    if regex_pattern:
                        import re

                        if not re.match(regex_pattern, str(field_value)):
                            json_summary[field] = {
                                "status": "failure",
                                "description": "Field exists but value does not match the required pattern.",
                                "regex_failure": True,
                            }
                            if self.include_field_values:
                                json_summary[field]["value"] = field_value
                            total_fields_failed += 1
                            continue

                    # Mark as success if field exists, has a value, is not 'unknown', and regex matches (if specified)
                    json_summary[field] = {
                        "status": "success",
                        "description": "Field exists and is valid.",
                    }
                    if self.include_field_values:
                        json_summary[field]["value"] = field_value
                    total_fields_passed += 1
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
                "total_fields_passed": total_fields_checked - total_fields_failed,
                "percentage_failed": round(
                    total_fields_failed / total_fields_checked * 100, 2
                ),
                "percentage_passed": round(
                    total_fields_passed / total_fields_checked * 100, 2
                ),
            }

            # Modify the JSON dumping based on the pretty_print_json option
            indent_value = 4 if self.pretty_print_json else None
            yield_record["json_summary"] = json.dumps(json_summary, indent=indent_value)

            # for each key value in record, add to yield_record
            for k, v in record.items():
                yield_record[k] = v

            yield yield_record

        # Log the run time
        logging.info(
            f'context="perf", checkcimquality has terminated, records_count="{records_count}", run_time="{round((time.time() - start), 3)}"'
        )


dispatch(CheckCimQuality, sys.argv, sys.stdin, sys.stdout, __name__)
