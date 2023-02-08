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
filehandler = logging.FileHandler(splunkhome + "/var/log/splunk/gsoctbox_gsocgennotable.log", 'a')
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

class GsocGenNotable(GeneratingCommand):

    '''
    Little too to generate a pseudo notable
    '''

    search_name = Option(
        doc='''
        **Syntax:** **search_name=****
        **Description:** value for search_name.''',
        require=True, default=None, validate=validators.Match("mode", r"^.*"))

    rule_name = Option(
        doc='''
        **Syntax:** **rule_name=****
        **Description:** value for rule_name.''',
       require=True, default=None, validate=validators.Match("mode", r"^.*"))

    rule_title = Option(
        doc='''
        **Syntax:** **rule_title=****
        **Description:** value for rule_title.''',
        require=True, default=None, validate=validators.Match("mode", r"^.*"))

    orig_host_bunit = Option(
        doc='''
        **Syntax:** **orig_host_bunit=****
        **Description:** value for orig_host_bunit.''',
        require=True, default=None, validate=validators.Match("mode", r"^.*"))

    severity = Option(
        doc='''
        **Syntax:** **severity=****
        **Description:** value for severity.''',
        require=True, default=None, validate=validators.Match("mode", r"^.*"))

    rule_description = Option(
        doc='''
        **Syntax:** **rule_description=****
        **Description:** value for rule_description.''',
        require=True, default=None, validate=validators.Match("mode", r"^.*"))

    orig_alert_category = Option(
        doc='''
        **Syntax:** **orig_alert_category=****
        **Description:** value for orig_alert_category.''',
        require=True, default=None, validate=validators.Match("mode", r"^.*"))

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

        # Define the query
        search = "| makeresults \n" +\
            "| eval " +\
            "search_name=\"" + self.search_name + "\", " +\
            "rule_name=\"" + self.rule_name + "\", " +\
            "rule_title=\"" + self.rule_title + "\", " +\
            "orig_host_bunit=\"" + self.orig_host_bunit + "\", " +\
            "severity=\"" + self.severity + "\", " +\
            "rule_description=\"" + self.rule_description + "\", " +\
            "orig_alert_category=\"" + self.orig_alert_category + "\" " +\
            " | collect index=notable"

        kwargs_oneshot = {
                            "earliest_time": "-5m",
                            "latest_time": "now",
                            "output_mode": "json",
                        }

        logging.debug("search=\"{}\"".format(search))

        # run the main report, every result is a Splunk search to be executed on its own thread
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

        except Exception as e:
            logging.error("failed to call the custom command with exception=\"{}\"".format(str(e)))
            raise ValueError("failed to call the custom command with exception=\"{}\"".format(str(e)))


dispatch(GsocGenNotable, sys.argv, sys.stdin, sys.stdout, __name__)
