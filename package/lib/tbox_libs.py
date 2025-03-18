#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Guilhem Marchand for Santander Digital"
__status__ = "PRODUCTION"

import os
import sys
import requests
import logging
from urllib.parse import urlencode
import urllib.parse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ["SPLUNK_HOME"]

sys.path.append(os.path.join(splunkhome, "etc", "apps", "TA-gsoctbox", "lib"))


def report_update_enablement(splunkd_uri, session_key, app, report_name, action):

    # Define an header for requests authenticated communications with splunkd
    header = {
        "Authorization": f"Splunk {session_key}",
        "Content-Type": "application/json",
    }

    if action not in ("enable", "disable"):
        raise Exception(
            f'Invalid value for action="{action}", valid options are: enable | disable'
        )

    else:
        report_name_encoded = urllib.parse.quote(report_name, safe="~()*!.'")
        record_url = f"{splunkd_uri}/servicesNS/nobody/{app}/saved/searches/{report_name_encoded}/{action}"

        logging.info(f'attempting to {action} report report_name="{report_name}"')
        try:
            response = requests.post(record_url, headers=header, verify=False)
            logging.info(
                f'action="success", report_name="{report_name}", http_status_code="{response.status_code}"'
            )
            response.raise_for_status()
            return "success"
        except Exception as e:
            logging.error(
                f'failure to update report report_name="{report_name}" with exception:"{str(e)}"'
            )
            raise Exception(str(e))
