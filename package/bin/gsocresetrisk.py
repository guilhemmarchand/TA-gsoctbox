#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Guilhem Marchand"
__version__ = "0.1.0"
__status__ = "PRODUCTION"

import os
import sys
import splunk
import splunk.entity
import json
import time
import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ['SPLUNK_HOME']

# set logging
filehandler = logging.FileHandler(splunkhome + "/var/log/splunk/gsoctbox_rba_gsocresetrisk.log", 'a')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s')
filehandler.setFormatter(formatter)
log = logging.getLogger()  # root logger - Good to get it only once.
for hdlr in log.handlers[:]:  # remove the existing file handlers
    if isinstance(hdlr,logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)      # set the new handler
# set the log level to INFO, DEBUG as the default is ERROR
log.setLevel(logging.INFO)

sys.path.append(os.path.join(splunkhome, 'etc', 'apps', 'TA-gsoctbox', 'lib'))

# import Splunk libs
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators
import splunklib.client as client
import splunklib.results as results

@Configuration(distributed=False)

class RiskReset(GeneratingCommand):

    '''
    RBA utility to reset the Risk Score
    '''

    risk_object_bunit = Option(
        doc='''
        **Syntax:** **risk_object_bunit=****
        **Description:** value for risk_object_bunit.''',
        require=True, default=None, validate=validators.Match("risk_object_bunit", r"^.*"))

    risk_object_type = Option(
        doc='''
        **Syntax:** **risk_object_type=****
        **Description:** value for risk_object_type.''',
        require=True, default=None, validate=validators.Match("risk_object_type", r"^.*"))

    risk_object = Option(
        doc='''
        **Syntax:** **risk_object=****
        **Description:** value for risk_object.''',
        require=True, default=None, validate=validators.Match("risk_object", r"^.*"))

    risk_message = Option(
        doc='''
        **Syntax:** **risk_message=****
        **Description:** value for risk_message.''',
        require=True, default=None, validate=validators.Match("risk_message", r"^.*"))

    risk_score = Option(
        doc='''
        **Syntax:** **risk_score=****
        **Description:** value for risk_score.''',
        require=True, default=None, validate=validators.Match("risk_score", r"^[\-|\d\.]*"))

    logging_level = Option(
        doc='''
        **Syntax:** **logging_level=****
        **Description:** value for logging_level.''',
        require=True, default="info", validate=validators.Match("mode", r"^(INFO|DEBUG|WARN|ERROR)"))


    def generate(self, **kwargs):

        # set loglevel
        log.setLevel(self.logging_level)

        # Get the session key
        session_key = self._metadata.searchinfo.session_key

        # Get splunkd port
        entity = splunk.entity.getEntity('/server', 'settings',
                                            namespace='TA-gsoctbox', sessionKey=session_key, owner='-')
        splunkd_port = entity['mgmtHostPort']
    
        # local service
        service = client.connect(
            token=str(session_key),
            owner="nobody",
            app="TA-gsoctbox",
            host="localhost",
            port=splunkd_port
        )

        #
        # STEP 1: Generate
        #

        if not float(self.risk_score)>0:

            yield_record = {
                '_time': time.time(),
                '_raw': "the current_risk_score=\"{}\" for risk_object_type=\"{}\", risk_object=\"{}\" is already equal to 0 or negative, it does not need to be reset".format(self.risk_score, self.risk_object_type, self.risk_object),                
                }
            yield yield_record

        else:

            # Generate a negative risk event
            search = "| makeresults" +\
                "\n| eval risk_object_bunit=\"" + self.risk_object_bunit + "\", risk_object_type=\"" + str(self.risk_object_type) + "\", risk_object=\"" + str(self.risk_object) + "\", risk_score=\"-" + str(self.risk_score) +  "\"" +\
                "\n| collectrisk search_name=\"AdHoc Risk Score\" risk_score=\"$result.risk_score$\" risk_object_field=\"$result.risk_object$\" risk_object_type=\"$result.risk_object_type$\" risk_message=\"" + str(self.risk_message) + "\""

            kwargs_oneshot = {
                                "earliest_time": "-5m",
                                "latest_time": "now",
                                "output_mode": "json",
                                "count": 0,
                            }

            logging.debug("search=\"{}\"".format(search))

            try:

                oneshotsearch_results = service.jobs.oneshot(search, **kwargs_oneshot)
                reader = results.JSONResultsReader(oneshotsearch_results)

                for item in reader:

                    if isinstance(item, dict):

                        yield_record = {
                            '_time': time.time(),
                            '_raw': item,
                            }
                        yield yield_record

                logging.info("successfully reset the risk score for risk_object=\"{}\", risk_object_type=\"{}\"".format(self.risk_object, self.risk_object_type))

            except Exception as e:
                logging.error("failed to reset the risk score with exception=\"{}\"".format(str(e)))
                raise ValueError("failed to reset the risk score with exception=\"{}\"".format(str(e)))

dispatch(RiskReset, sys.argv, sys.stdin, sys.stdout, __name__)
