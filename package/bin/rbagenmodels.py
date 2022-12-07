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
filehandler = logging.FileHandler(splunkhome + "/var/log/splunk/gsoctbox_rba_genmodels.log", 'a')
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

class RbaGenModels(GeneratingCommand):

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
                        for bunit in result_bunit_list:
                            bunit_list.append(bunit)
                    except Exception as e:
                        raise Exception('Could not find the expected field risk_object_bunit from upstream results with exception=\"{}\"'.format(str(e)))

        except Exception as e:
            logging.error("failed to run the bunit provider list with exception=\"{}\"".format(str(e)))
            raise Exception("failed to run the bunit provider list with exception=\"{}\"".format(str(e)))

        logging.debug("bunit_list=\"{}\"".format(bunit_list))

        ################################################
        # Step 2: for each BUNIT, create a model per KPI
        ################################################

        # Loop through the list of business units, and proceed
        for bunit in bunit_list:

            # loop through the list of KPIs
            for kpi in kpis_list:

                # define:

                # - the name of model id (extract the second segment of the metric_name)
                modelid = "rba_" + str(bunit).replace(" ", "_").replace("-", "_").lower() + "_" + kpi.split(".")[1]

                # - the search logic that generates and train the ML model

                mlmodel_gen_search = "| mstats avg(rba.cummulative_risk_score) as rba.cummulative_risk_score where index=security_siem_metrics " +\
                    "risk_object_bunit=\"" + bunit.replace("|", "\\|") + "\" by risk_object_bunit span=1h" +\
                    "\n| eval factor=strftime(_time, \"%w%H\")" +\
                    "\n| fit DensityFunction rba.cummulative_risk_score lower_threshold=0.005 upper_threshold=0.005 into " + modelid  + " by factor" +\
                    "\n| rex field=BoundaryRanges \"(-Infinity:(?<LowerBound>[\d|\.]*))|((?<UpperBound>[\d|\.]*):Infinity)\"" +\
                    "\n| foreach LowerBound UpperBound [ eval <<FIELD>> = if(isnum('<<FIELD>>'), '<<FIELD>>', 0) ]" +\
                    "\n| fields _time rba.cummulative_risk_score LowerBound UpperBound"

                # set kwargs
                kwargs = {
                                    "earliest_time": "-90d",
                                    "latest_time": "now",
                                    "output_mode": "json",
                                    "count": 0,
                                }

                # process the search
                logging.debug("mlmodel_gen_search=\"{}\", earliest=\"{}\", latest=\"{}\"".format(mlmodel_gen_search, kwargs.get('earliest_time'), kwargs.get('latest_time')))

                # run the main report, every result is a Splunk search to be executed on its own thread

                # perf counters
                start_time = time.time()
                results_count = 0

                try:

                    oneshotsearch_results = service.jobs.oneshot(mlmodel_gen_search, **kwargs)
                    reader = results.JSONResultsReader(oneshotsearch_results)

                    for item in reader:
                        if isinstance(item, dict):
                            # log
                            logging.debug("result=\"{}\"".format(item))
                            results_count+=1

                    # log final
                    runtime = round(time.time()-start_time, 3)
                    logging.info("finished ML train search for bunit=\"{}\", kpi=\"{}\", results_count=\"{}\", runtime=\"{}\"".format(bunit, kpi, results_count, runtime))

                    # yield results
                    yield_record = {
                        '_time': time.time(),
                        'action': 'success',
                        'bunit': bunit,
                        'kpi': kpi,
                        'modelid': modelid,
                        'results_count': results_count,
                        'runtime': runtime,
                        'search': mlmodel_gen_search,
                        '_raw': "successfully processed ML model training"
                        }

                    yield {
                        '_time': yield_record.get('_time'),
                        '_raw': yield_record,
                        'action': 'success',
                        'bunit': yield_record.get('bunit'),
                        'kpi': yield_record.get('kpi'),
                        'modelid': yield_record.get('modelid'),
                        'results_count': yield_record.get('results_count'),
                        'runtime': yield_record.get('runtime'),
                        'search': yield_record.get('mlmodel_gen_search'),
                    }

                except Exception as e:
                    logging.error("failed to run the bunit ML model train search with exception=\"{}\"".format(str(e)))

                    # yield results
                    yield_record = {
                        '_time': time.time(),
                        'action': 'failure',
                        'exception': str(e),
                        'bunit': bunit,
                        'kpi': kpi,
                        'modelid': modelid,
                        'results_count': results_count,
                        'search': mlmodel_gen_search,
                        '_raw': "failed processing ML model training"
                        }

                    yield {
                        '_time': yield_record.get('_time'),
                        '_raw': yield_record,
                        'action': 'failure',
                        'exception': str(e),
                        'bunit': yield_record.get('bunit'),
                        'kpi': yield_record.get('kpi'),
                        'modelid': yield_record.get('modelid'),
                        'results_count': yield_record.get('results_count'),
                        'search': yield_record.get('mlmodel_gen_search'),
                    }

dispatch(RbaGenModels, sys.argv, sys.stdin, sys.stdout, __name__)
