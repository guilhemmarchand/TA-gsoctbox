#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Guilhem Marchand for Santander Digital"
__status__ = "PRODUCTION"

import os
import sys
import splunk
import splunk.entity
import requests
import logging
from urllib.parse import urlencode
import urllib.parse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ['SPLUNK_HOME']

sys.path.append(os.path.join(splunkhome, 'etc', 'apps', 'TA-gsoctbox', 'lib'))

def report_update_enablement(session_key, app, report_name, action):

    # Get splunkd port
    entity = splunk.entity.getEntity('/server', 'settings',
                                        namespace='TA-gsoctbox', sessionKey=session_key, owner='-')
    splunkd_port = entity['mgmtHostPort']

    # Define an header for requests authenticated communications with splunkd
    header = {
        'Authorization': 'Splunk %s' % session_key,
        'Content-Type': 'application/json'}

    if action not in ("enable", "disable"):
        raise Exception("Invalid value for action=\"{}\", valid options are: enable | disable".format(action))

    else:
        report_name_encoded = urllib.parse.quote(str(report_name))
        record_url = 'https://localhost:%s/servicesNS/nobody/%s/saved/searches/%s/%s' % (splunkd_port, app, report_name_encoded, action)

        logging.info("attempting to {} report report_name=\"{}\"".format(action, report_name))
        try:
            response = requests.post(record_url, headers=header, verify=False)
            logging.info("action=\"success\", report_name=\"{}\"".format(report_name))
            return "success"
        except Exception as e:
            logging.error("failure to update report report_name=\"{}\" with exception:\"{}\"".format(report_name, str(e)))
            raise Exception(str(e))
