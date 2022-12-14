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
import requests
import time
import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ['SPLUNK_HOME']

# set logging
filehandler = logging.FileHandler(splunkhome + "/var/log/splunk/gsoctbox_rba_renderoutliers.log", 'a')
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

class RbaRenderOutliers(GeneratingCommand):

    app = Option(
        doc='''
        **Syntax:** **app=****
        **Description:** The app namespace, this conditions where models are going to be created and managed.''',
        require=False, default="search", validate=validators.Match("app", r"^.*"))

    owner = Option(
        doc='''
        **Syntax:** **owner=****
        **Description:** The owner of ML models to be genrated.''',
        require=False, default="admin", validate=validators.Match("owner", r"^.*"))

    bunit_search_provider = Option(
        doc='''
        **Syntax:** **bunit_search_provider=****
        **Description:** The search logic to return the list of the business units to be processed.''',
        require=True, default=None, validate=validators.Match("bunit_search_provider", r"^.*"))

    bunit_search_provider_earliest = Option(
        doc='''
        **Syntax:** **bunit_search_provider_earliest=****
        **Description:** Earliest time quantifier for the bunit provider.''',
        require=True, default=None, validate=validators.Match("bunit_search_provider_earliest", r"^.*"))

    bunit_search_provider_latest = Option(
        doc='''
        **Syntax:** **bunit_search_provider_latest=****
        **Description:** Earliest time quantifier for the bunit provider.''',
        require=True, default=None, validate=validators.Match("bunit_search_provider_latest", r"^.*"))

    kpis = Option(
        doc='''
        **Syntax:** **kpis=****
        **Description:** The list of KPIs for which a model is going to be created and trained.''',
        require=True, default=None, validate=validators.Match("kpis", r"^.*"))

    earliest_time = Option(
        doc='''
        **Syntax:** **earliest_time=****
        **Description:** The earliest time quantifier for the mstats ML rendering search.''',
        require=False, default="-90d", validate=validators.Match("earliest_time", r"^.*$"))

    latest_time = Option(
        doc='''
        **Syntax:** **latest_time=****
        **Description:** The latest time quantifier for the mstats ML rendering search.''',
        require=False, default="now", validate=validators.Match("latest_time", r"^.*$"))

    alert_upper_reached = Option(
        doc='''
        **Syntax:** **alert_upper_reached=****
        **Description:** Alert if the bunit reached the upper bound threshold. (default: True)''',
        require=False, default=True)

    alert_lower_reached = Option(
        doc='''
        **Syntax:** **alert_lower_reached=****
        **Description:** Alert if the bunit reached the upper bound threshold. (default: False)''',
        require=False, default=False)

    def generate(self, **kwargs):

        # set loglevel
        loglevel = 'INFO'
        conf_file = "ta_gsoctbox_settings"
        confs = self.service.confs[str(conf_file)]
        for stanza in confs:
            if stanza.name == 'logging':
                for stanzakey, stanzavalue in stanza.content.items():
                    if stanzakey == "loglevel":
                        loglevel = stanzavalue
        logginglevel = logging.getLevelName(loglevel)
        log.setLevel(logginglevel)

        # get current user
        username = self._metadata.searchinfo.username

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
            app=self.app,
            host="localhost",
            port=splunkd_port
        )

        # Data collection
        collection_name = "kv_rba_bunit_mlmodels_config"
        collection = service.kvstore[collection_name]        

        # kpis
        # We expect a comma separated list of KPIs, or a native list
        if not isinstance(self.kpis, list):
            kpis_list = self.kpis.split(",")
        else:
            kpis_list = self.kpis

        ######################################
        # Step 1: get the list of active BUNIT
        ######################################

        # store in a list the active entities
        bunit_list = []

        # set kwargs
        kwargs_oneshot = {
                            "earliest_time": self.bunit_search_provider_earliest,
                            "latest_time": self.bunit_search_provider_latest,
                            "output_mode": "json",
                            "count": 0,
                        }

        logging.debug("search=\"{}\", earliest=\"{}\", latest=\"{}\"".format(self.bunit_search_provider, self.bunit_search_provider_earliest, self.bunit_search_provider_latest))

        # run the main report, every result is a Splunk search to be executed on its own thread
        try:

            oneshotsearch_results = service.jobs.oneshot(self.bunit_search_provider, **kwargs_oneshot)
            reader = results.JSONResultsReader(oneshotsearch_results)

            for item in reader:
                if isinstance(item, dict):
                    try:
                        result_bunit_list = item.get('risk_object_bunit')
                        
                        # check if is a list
                        if isinstance(result_bunit_list, list):
                            for bunit in result_bunit_list:
                                bunit_list.append(bunit)
                        else:
                            bunit_list.append(result_bunit_list)

                    except Exception as e:
                        raise Exception('Could not find the expected field risk_object_bunit from upstream results with exception=\"{}\"'.format(str(e)))

        except Exception as e:
            logging.error("failed to run the bunit provider list with exception=\"{}\"".format(str(e)))
            raise Exception("failed to run the bunit provider list with exception=\"{}\"".format(str(e)))

        logging.debug("bunit_list=\"{}\"".format(bunit_list))

        ######################################################
        # Step 2: for each BUNIT, investigate outliers per KPI
        ######################################################

        # store outliers results
        outliers_results = []

        # Loop through the list of business units, and proceed
        for bunit in bunit_list:

            # loop through the list of KPIs
            for kpi in kpis_list:

                # check if we have a configuration in the KVstore for that entity
                # if we do not, add a new record with the default threshold values

                try:

                    # Define the KV query
                    query_string = {
                        "$and": [ {
                            'bunit': bunit,
                            'kpi': kpi,
                            } ]
                        }    

                    # try get to get the key
                    kvrecord = collection.data.query(query=(json.dumps(query_string)))[0]
                    key = kvrecord.get('_key')

                except Exception as e:
                    key = None

                # this bunit is new
                if not key:
                    logging.error("The bunit=\"{}\" and kpi=\"{}\" has not been trained yet, there are no records available in the KVstore collection".format(bunit, kpi))

                else:
                    logging.info("processing outliers detection for bunit=\"{}\", kpi=\"{}\"".format(bunit, kpi))

                mlmodel_root_search = "| mstats avg(" + kpi + ") as " + kpi + " where index=security_siem_metrics " +\
                    "risk_object_bunit=\"" + bunit.replace("|", "\\|") + "\" by risk_object_bunit span=1h" +\
                    "\n| eval factor=strftime(_time, \"" + kvrecord.get("time_factor") + "\")" +\
                    "\n| apply " + kvrecord.get("modelid") +\
                    "\n| rex field=BoundaryRanges \"(-Infinity:(?<LowerBound>[\d|\.]*))|((?<UpperBound>[\d|\.]*):Infinity)\"" +\
                    "\n| foreach LowerBound UpperBound [ eval <<FIELD>> = if(isnum('<<FIELD>>'), '<<FIELD>>', 0) ]" +\
                    "\n| fields _time " + kpi + " LowerBound UpperBound | sort 0 - _time"

                mlmodel_render_search = mlmodel_root_search + " | head 1"

                # set kwargs
                kwargs = {
                                    "earliest_time": self.earliest_time,
                                    "latest_time": self.latest_time,
                                    "output_mode": "json",
                                    "count": 0,
                                }

                # process the search
                logging.info("bunit=\"{}\", kpi=\"{}\", mlmodel_render_search=\"{}\", earliest=\"{}\", latest=\"{}\"".format(bunit, kpi, mlmodel_render_search, kwargs.get('earliest_time'), kwargs.get('latest_time')))

                # run the main report, every result is a Splunk search to be executed on its own thread

                # perf counters
                start_time = time.time()
                results_count = 0

                try:

                    oneshotsearch_results = service.jobs.oneshot(mlmodel_render_search, **kwargs)
                    reader = results.JSONResultsReader(oneshotsearch_results)

                    for item in reader:
                        if isinstance(item, dict):
                            # log
                            logging.debug("result=\"{}\"".format(item))
                            results_count+=1

                            # Investigate outliers
                            current_kpi_value = float(item.get(kpi))
                            lowerbound_value = float(item.get('LowerBound'))
                            upperbound_value = float(item.get('UpperBound'))

                            # LowerBound reached
                            if self.alert_lower_reached:
                                if current_kpi_value<lowerbound_value:
                                    outliers_record = {
                                        '_time': time.time(),
                                        '_raw': {
                                            'bunit': bunit,
                                            'kpi': kpi,
                                            'detection_status': 'outliers_detected',
                                            'current_kpi_value': current_kpi_value,
                                            'lowerbound_value': lowerbound_value,
                                            'mlmodel_root_search': mlmodel_root_search,
                                            'modelid': kvrecord.get("modelid"),
                                            'result': 'Outliers detected for bunit=\"{}\", kpi=\"{}\" with LowerBound threshold reached'.format(bunit, kpi),
                                        },
                                        'bunit': bunit,
                                        'kpi': kpi,
                                        'detection_status': 'outliers_detected',
                                        'current_kpi_value': current_kpi_value,
                                        'lowerbound_value': lowerbound_value,
                                        'mlmodel_root_search': mlmodel_root_search,
                                        'modelid': kvrecord.get("modelid"),
                                        'result': 'Outliers detected for bunit=\"{}\", kpi=\"{}\" with LowerBound threshold reached'.format(bunit, kpi),
                                    }
                                else:
                                    outliers_record = {
                                        '_time': time.time(),
                                        '_raw': {
                                            'bunit': bunit,
                                            'kpi': kpi,
                                            'detection_status': 'outliers_passed',
                                            'current_kpi_value': current_kpi_value,
                                            'lowerbound_value': lowerbound_value,
                                            'mlmodel_root_search': mlmodel_root_search,
                                            'modelid': kvrecord.get("modelid"),
                                            'result': 'There are no outliers detected for bunit=\"{}\", kpi=\"{}\", LowerBound thresold not reached'.format(bunit, kpi),
                                        },
                                        'bunit': bunit,
                                        'kpi': kpi,
                                        'detection_status': 'outliers_passed',
                                        'current_kpi_value': current_kpi_value,
                                        'lowerbound_value': lowerbound_value,
                                        'mlmodel_root_search': mlmodel_root_search,
                                        'modelid': kvrecord.get("modelid"),
                                        'result': 'There are no outliers detected for bunit=\"{}\", kpi=\"{}\", LowerBound thresold not reached'.format(bunit, kpi),
                                    }
                                # append to our results
                                outliers_results.append(outliers_record)

                            # UpperBound reached
                            if self.alert_upper_reached:
                                if current_kpi_value>upperbound_value:
                                    outliers_record = {
                                        '_time': time.time(),
                                        '_raw': {
                                            'bunit': bunit,
                                            'kpi': kpi,
                                            'detection_status': 'outliers_detected',
                                            'current_kpi_value': current_kpi_value,
                                            'upperbound_value': upperbound_value,
                                            'mlmodel_root_search': mlmodel_root_search,
                                            'modelid': kvrecord.get("modelid"),
                                            'result': 'Outliers detected for bunit=\"{}\", kpi=\"{}\" with UpperBound threshold reached'.format(bunit, kpi),
                                        },
                                        'bunit': bunit,
                                        'kpi': kpi,
                                        'detection_status': 'outliers_detected',
                                        'current_kpi_value': current_kpi_value,
                                        'upperbound_value': upperbound_value,
                                        'mlmodel_root_search': mlmodel_root_search,
                                        'modelid': kvrecord.get("modelid"),
                                        'result': 'Outliers detected for bunit=\"{}\", kpi=\"{}\" with UpperBound threshold reached'.format(bunit, kpi),
                                    }
                                else:
                                    outliers_record = {
                                        '_time': time.time(),
                                        '_raw': {
                                            'bunit': bunit,
                                            'kpi': kpi,
                                            'detection_status': 'outliers_passed',
                                            'current_kpi_value': current_kpi_value,
                                            'upperbound_value': upperbound_value,
                                            'mlmodel_root_search': mlmodel_root_search,
                                            'modelid': kvrecord.get("modelid"),
                                            'result': 'There are no outliers detected for bunit=\"{}\", kpi=\"{}\", UpperBound thresold not reached'.format(bunit, kpi),
                                        },
                                        'bunit': bunit,
                                        'kpi': kpi,
                                        'detection_status': 'outliers_passed',
                                        'current_kpi_value': current_kpi_value,
                                        'upperbound_value': upperbound_value,
                                        'mlmodel_root_search': mlmodel_root_search,
                                        'modelid': kvrecord.get("modelid"),
                                        'result': 'There are no outliers detected for bunit=\"{}\", kpi=\"{}\", UpperBound thresold not reached'.format(bunit, kpi),
                                    }
                                # append to our results
                                outliers_results.append(outliers_record)

                    # log end
                    logging.info("bunit=\"{}\", kpi=\"{}\", finished processing search, runtime=\"{}\"".format(bunit, kpi, round(time.time()-start_time, 3)))

                except Exception as e:
                    logging.error("failed to process the search for bunit=\"{}\", kpi=\"{}\", modelid=\"{}\", exception=\"{}\"".format(bunit, kpi, mlmodel_render_search, str(e)))

        # render results
        for outlier_result in outliers_results:

            # yield
            yield outlier_result

dispatch(RbaRenderOutliers, sys.argv, sys.stdin, sys.stdout, __name__)
