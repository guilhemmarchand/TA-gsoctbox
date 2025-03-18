#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Guilhem Marchand for Santander Digital"
__status__ = "PRODUCTION"

import os
import sys
import urllib3
import time
import json
import logging
from logging.handlers import RotatingFileHandler

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# set splunkhome
splunkhome = os.environ["SPLUNK_HOME"]

# set logging
filehandler = RotatingFileHandler(
    f"{splunkhome}/var/log/splunk/gsoctbox_gsocmassdisabler.log",
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

# append libs
sys.path.append(os.path.join(splunkhome, "etc", "apps", "TA-gsoctbox", "lib"))

from splunklib.searchcommands import (
    dispatch,
    GeneratingCommand,
    Configuration,
    Option,
    validators,
)
import splunklib.client as client
import splunklib.results as results

# import TA-gsoctbox libs
from tbox_libs import report_update_enablement


@Configuration(distributed=False)
class GsocMassDisabler(GeneratingCommand):

    mode = Option(
        doc="""
        **Syntax:** **mode=****
        **Description:** value for mode.""",
        require=False,
        default="simulation",
        validate=validators.Match("mode", r"^(simulation|live)$"),
    )

    es_forbidden_apps = Option(
        doc="""
        **Syntax:** **es_forbidden_apps, a comma separated list of apps which enabled scheduled are forbidden on ES SHC****
        **Description:** es_forbidden_apps, a comma separated list of apps which enabled scheduled are forbidden on ES SHC.""",
        require=True,
        default=None,
        validate=validators.Match("es_forbidden_apps", r"^.*$"),
    )

    adhoc_forbidden_apps = Option(
        doc="""
        **Syntax:** **adhoc_forbidden_apps, a comma separated list of apps which enabled scheduled are forbidden on Adhoc SHC****
        **Description:** es_forbidden_apps, a comma separated list of apps which enabled scheduled are forbidden on Adhoc SHC.""",
        require=True,
        default=None,
        validate=validators.Match("adhoc_forbidden_apps", r"^.*$"),
    )

    def generate(self, **kwargs):

        if self:

            # start perf duration counter
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

            # Get the session key
            session_key = self._metadata.searchinfo.session_key

            # end of get configuration

            # Apps forbidden on ES
            es_forbidden_apps = []
            if not isinstance(self.es_forbidden_apps, list):
                es_forbidden_apps = self.es_forbidden_apps.split(",")
            else:
                es_forbidden_apps = self.es_forbidden_apps

            # Apps forbidden on Adhoc SHC
            adhoc_forbidden_apps = []
            if not isinstance(self.adhoc_forbidden_apps, list):
                adhoc_forbidden_apps = self.adhoc_forbidden_apps.split(",")
            else:
                adhoc_forbidden_apps = self.adhoc_forbidden_apps

            # end of investigate args

            #
            # Task 0: retrieve the list of searches
            #

            savedsearches_list = []

            # Combine both lists into a single list
            apps_filter = es_forbidden_apps + adhoc_forbidden_apps

            # Create a list of strings with the desired format
            strings = [f'app="{item}"' for item in apps_filter]

            # Join the list of strings with " OR " separator
            mysearch_string = " OR ".join(strings)

            # search
            search = (
                "| rest splunk_server=local count=0 /services/saved/searches"
                + "\n | where (is_scheduled=1 AND disabled=0)"
                + "\n | rename title as savedsearch_name, eai:acl.app as app, eai:acl.owner as owner"
                + "\n | table savedsearch_name, app, owner, disabled, cron_schedule, search"
                + "\n | search %s" % (mysearch_string)
            )

            # set kwargs
            kwargs_oneshot = {
                "earliest_time": "-5m",
                "latest_time": "now",
                "output_mode": "json",
                "count": 0,
            }

            logging.info(
                'search="{}", earliest="{}", latest="{}"'.format(
                    kwargs_oneshot.get("earliest_time"),
                    kwargs_oneshot.get("latest_time"),
                    search,
                )
            )

            # run the main report, every result is a Splunk search to be executed on its own thread
            try:

                oneshotsearch_results = self.service.jobs.oneshot(
                    search, **kwargs_oneshot
                )
                reader = results.JSONResultsReader(oneshotsearch_results)

                for item in reader:
                    if isinstance(item, dict):

                        savedsearches_list.append(
                            {
                                "app": item.get("app"),
                                "owner": item.get("owner"),
                                "savedsearch_name": item.get("savedsearch_name"),
                                "disabled": int(item.get("disabled")),
                            }
                        )

            except Exception as e:
                logging.error(
                    'failed to run the provider search with exception="{}"'.format(
                        str(e)
                    )
                )
                raise Exception(
                    'failed to run the provider search with exception="{}"'.format(
                        str(e)
                    )
                )

            if not len(savedsearches_list) > 0:

                msg = "The rest search did not produce any results, likely we have no enabled searches in none of the applications submitted, nothing to do."
                yield_record = {
                    "action": "disable",
                    "mode": self.mode,
                    "result": msg,
                    "search": search,
                }

                # yield
                yield {
                    "_time": time.time(),
                    "_raw": yield_record,
                }

                logging.info(json.dumps(msg))

            #
            # task 1: identify the SH layer, are we running on ES or Adhoc?
            #

            es_sh_layer = False
            adhoc_sh_layer = False

            # get the list of local apps
            local_apps = []
            for app in self.service.apps:
                local_apps.append(app.name)

            # if SplunkEnterpriseSecurity
            if "SplunkEnterpriseSecuritySuite" in local_apps:
                es_sh_layer = True
                adhoc_sh_layer = False
            else:
                es_sh_layer = False
                adhoc_sh_layer = True

            #
            # task 2: identify the SH layer, are we running on ES or Adhoc?
            #

            # A list to store the action to be performed
            process_action = []

            #
            # loop through upstream records
            #

            # Loop in the results
            for record in savedsearches_list:

                record_app = record.get("app")
                record_owner = record.get("owner")
                record_savedsearch_name = record.get("savedsearch_name")
                record_disabled = int(record.get("disabled"))

                logging.debug(
                    'investigating app="{}", savedsearch_name="{}", owner="{}", disabled="{}"'.format(
                        record_app,
                        record_savedsearch_name,
                        record_owner,
                        record_disabled,
                    )
                )

                # if running on ES
                if es_sh_layer:

                    if record_app in es_forbidden_apps and record_disabled == 0:

                        logging.info(
                            'the savedsearch_name="{}" is currently enabled, disabled="{}", app="{}", this search is part of a forbidden application in this Search Layer and will be disabled'.format(
                                record_savedsearch_name, record_disabled, record_app
                            )
                        )
                        process_action.append(
                            {
                                "savedsearch_name": record_savedsearch_name,
                                "app": record_app,
                                "owner": record_owner,
                                "disabled": record_disabled,
                            }
                        )

                # if running on Adhoc
                elif adhoc_sh_layer:

                    if record_app in adhoc_forbidden_apps and record_disabled == 0:

                        logging.info(
                            'the savedsearch_name="{}" is currently enabled, disabled="{}", app="{}", this search is part of a forbidden application in this Search Layer and will be disabled'.format(
                                record_savedsearch_name, record_disabled, record_app
                            )
                        )
                        process_action.append(
                            {
                                "savedsearch_name": record_savedsearch_name,
                                "app": record_app,
                                "owner": record_owner,
                                "disabled": record_disabled,
                            }
                        )

            #
            # Task 3: now that we have established the list of actions, we do the job, for each record in the process_action list, act accordingly
            #

            if len(process_action) > 0:

                for record in process_action:

                    if not self.mode == "simulation":

                        yield_record = {
                            "action": "disable",
                            "app": record.get("app"),
                            "savedsearch_name": record.get("savedsearch_name"),
                            "owner": record.get("owner"),
                        }

                        try:
                            disabled_results = report_update_enablement(
                                self._metadata.searchinfo.splunkd_uri,
                                session_key,
                                record.get("app"),
                                record.get("savedsearch_name"),
                                "disable",
                            )

                            # check response
                            if disabled_results == "success":
                                yield_record["result"] = "success"
                            else:
                                yield_record["result"] = "failure"

                            # yield
                            yield {
                                "_time": time.time(),
                                "_raw": yield_record,
                            }

                        except Exception as e:

                            yield_record["result"] = "failure"
                            yield_record["exception"] = str(e)

                            # yield
                            yield {
                                "_time": time.time(),
                                "_raw": yield_record,
                            }

                    else:

                        yield_record = {
                            "action": "simulation",
                            "result": "running in simulation, nothing was changed",
                            "app": record.get("app"),
                            "savedsearch_name": record.get("savedsearch_name"),
                            "owner": record.get("owner"),
                        }

                        yield {
                            "_time": time.time(),
                            "_raw": yield_record,
                        }

            else:

                yield_record = {
                    "message": "No scheduled reports were detected as enabled in a forbidden application at this stage, nothing to do.",
                    "es_sh_layer": es_sh_layer,
                    "adhoc_sh_layer": adhoc_sh_layer,
                    "mode": self.mode,
                    "es_forbidden_apps": es_forbidden_apps,
                    "adhoc_forbidden_apps": adhoc_forbidden_apps,
                }

                yield {
                    "_time": time.time(),
                    "_raw": yield_record,
                }

                logging.info(json.dumps(yield_record))

            logging.info(
                'gsocmassdisabler has terminated, run_time="{}"'.format(
                    str(time.time() - start)
                )
            )


dispatch(GsocMassDisabler, sys.argv, sys.stdin, sys.stdout, __name__)
