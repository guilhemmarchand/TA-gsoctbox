#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Guilhem Marchand"
__version__ = "0.1.0"
__status__ = "PRODUCTION"

import os
import sys
import time
import logging
from logging.handlers import RotatingFileHandler
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ["SPLUNK_HOME"]

# set logging
filehandler = RotatingFileHandler(
    f"{splunkhome}/var/log/splunk/gsoctbox_rba_gsocresetrisk.log",
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
    GeneratingCommand,
    Configuration,
    Option,
    validators,
)
import splunklib.results as results


@Configuration(distributed=False)
class RiskReset(GeneratingCommand):
    """
    RBA utility to reset the Risk Score
    """

    risk_object_bunit = Option(
        doc="""
        **Syntax:** **risk_object_bunit=****
        **Description:** value for risk_object_bunit.""",
        require=True,
        default=None,
        validate=validators.Match("risk_object_bunit", r"^.*"),
    )

    risk_object_type = Option(
        doc="""
        **Syntax:** **risk_object_type=****
        **Description:** value for risk_object_type.""",
        require=True,
        default=None,
        validate=validators.Match("risk_object_type", r"^.*"),
    )

    risk_object = Option(
        doc="""
        **Syntax:** **risk_object=****
        **Description:** value for risk_object.""",
        require=True,
        default=None,
        validate=validators.Match("risk_object", r"^.*"),
    )

    risk_message = Option(
        doc="""
        **Syntax:** **risk_message=****
        **Description:** value for risk_message.""",
        require=True,
        default=None,
        validate=validators.Match("risk_message", r"^.*"),
    )

    risk_score = Option(
        doc="""
        **Syntax:** **risk_score=****
        **Description:** value for risk_score.""",
        require=True,
        default=None,
        validate=validators.Match("risk_score", r"^[\-|\d\.]*"),
    )

    def generate(self, **kwargs):

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

        #
        # STEP 1: Generate
        #

        if not float(self.risk_score) > 0:

            yield_record = {
                "_time": time.time(),
                "_raw": f'the current_risk_score="{self.risk_score}" for risk_object_type="{self.risk_object_type}", risk_object="{self.risk_object}" is already equal to 0 or negative, it does not need to be reset',
            }
            yield yield_record

        else:

            # Generate a negative risk event
            search = (
                f"| makeresults"
                + f'\n| eval risk_object_bunit="{self.risk_object_bunit}", risk_object_type="{str(self.risk_object_type)}", risk_object="{str(self.risk_object)}", risk_score="-{str(self.risk_score)}"'
                + f'\n| collectrisk search_name="AdHoc Risk Score" risk_score="$result.risk_score$" risk_object_field="$result.risk_object$" risk_object_type="$result.risk_object_type$" risk_message="{str(self.risk_message)}"'
            )

            kwargs_oneshot = {
                "earliest_time": "-5m",
                "latest_time": "now",
                "output_mode": "json",
                "count": 0,
            }

            logging.debug(f'search="{search}"')

            try:

                oneshotsearch_results = self.service.jobs.oneshot(
                    search, **kwargs_oneshot
                )
                reader = results.JSONResultsReader(oneshotsearch_results)

                for item in reader:

                    if isinstance(item, dict):

                        yield_record = {
                            "_time": time.time(),
                            "_raw": item,
                        }
                        yield yield_record

                logging.info(
                    f'successfully reset the risk score for risk_object="{self.risk_object}", risk_object_type="{self.risk_object_type}"'
                )

            except Exception as e:
                logging.error(
                    f'failed to reset the risk score with exception="{str(e)}"'
                )
                raise ValueError(
                    f'failed to reset the risk score with exception="{str(e)}"'
                )


dispatch(RiskReset, sys.argv, sys.stdin, sys.stdout, __name__)
