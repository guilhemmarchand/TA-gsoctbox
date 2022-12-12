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
filehandler = logging.FileHandler(splunkhome + "/var/log/splunk/gsoctbox_rba_rbarenderoutliersperbunit.log", 'a')
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

    bunit = Option(
        doc='''
        **Syntax:** **bunit=****
        **Description:** The bunit to be processed.''',
        require=True, default=None, validate=validators.Match("bunit", r"^.*"))

    kpi = Option(
        doc='''
        **Syntax:** **kpi=****
        **Description:** The kpi to be rendered.''',
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
            app=self.app,
            host="localhost",
            port=splunkd_port
        )

        # Data collection
        collection_name = "kv_rba_bunit_mlmodels_config"
        collection = service.kvstore[collection_name]        

        ##################################################################
        # retrieve the entity models ID and configuration, render outliers
        ##################################################################

        # get the KVstore record for that bunit / kpi
        try:

            # Define the KV query
            query_string = {
                "$and": [ {
                    'bunit': self.bunit,
                    'kpi': self.kpi,
                    } ]
                }    

            # try get to get the key
            kvrecord = collection.data.query(query=(json.dumps(query_string)))[0]
            key = kvrecord.get('_key')

        except Exception as e:
            key = None
            raise Exception("RBA model outliers are not ready yet for this bunit and kpi, the entity needs to be trained first")

        # this bunit and kpi are ready
        if key:

            logging.info("processing outliers rendering for bunit=\"{}\", kpi=\"{}\"".format(self.bunit, self.kpi))

            mlmodel_render_search = "| mstats avg(" + self.kpi + ") as " + self.kpi + " where index=security_siem_metrics " +\
                "risk_object_bunit=\"" + self.bunit + "\" by risk_object_bunit span=1h" +\
                "\n| eval factor=strftime(_time, \"" + kvrecord.get("time_factor") + "\")" +\
                "\n| apply " + kvrecord.get("modelid") +\
                "\n| rex field=BoundaryRanges \"(-Infinity:(?<LowerBound>[\d|\.]*))|((?<UpperBound>[\d|\.]*):Infinity)\"" +\
                "\n| foreach LowerBound UpperBound [ eval <<FIELD>> = if(isnum('<<FIELD>>'), '<<FIELD>>', 0) ]" +\
                "\n| fields _time " + self.kpi + " LowerBound UpperBound"

            # set kwargs
            kwargs = {
                                "earliest_time": self.earliest_time,
                                "latest_time": self.latest_time,
                                "search_mode": "normal",
                                "preview": False,
                                "time_format": "%s",
                                "count": 0,
                                "output_mode": "json",
                            }

            # process the search
            logging.info("bunit=\"{}\", kpi=\"{}\", mlmodel_render_search=\"{}\", earliest=\"{}\", latest=\"{}\"".format(self.bunit, self.kpi, mlmodel_render_search, kwargs.get('earliest_time'), kwargs.get('latest_time')))

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

                        yield_record = {}

                        # Investigate outliers
                        try:
                            timeevent = float(item.get('_time'))
                            yield_record['_time'] = timeevent
                        except Exception as e:
                            timeevent = None

                        try:
                            current_kpi_value = float(item.get(self.kpi))
                            yield_record[self.kpi] = current_kpi_value
                        except Exception as e:
                            current_kpi_value = None

                        try:
                            lowerbound_value = float(item.get('LowerBound'))
                            yield_record['LowerBound'] = lowerbound_value
                        except Exception as e:
                            lowerbound_value = None
                        
                        try:
                            upperbound_value = float(item.get('UpperBound'))
                            yield_record['UpperBound'] = upperbound_value
                        except Exception as e:
                            upperbound_value = None

                        yield {
                            '_time': timeevent,
                            '_raw': yield_record,
                            self.kpi: current_kpi_value,
                            'LowerBound': lowerbound_value,
                            'UpperBound': upperbound_value,
                        }

                        logging.debug("result=\"{}\"".format(json.dumps(item)))

                # log end
                logging.info("bunit=\"{}\", kpi=\"{}\", finished processing search, runtime=\"{}\"".format(self.bunit, self.kpi, round(time.time()-start_time, 3)))

            except Exception as e:
                logging.error("failed to process the search for bunit=\"{}\", kpi=\"{}\", modelid=\"{}\", exception=\"{}\"".format(self.bunit, self.kpi, mlmodel_render_search, str(e)))
                raise Exception("failed to process the search for bunit=\"{}\", kpi=\"{}\", modelid=\"{}\", exception=\"{}\"".format(self.bunit, self.kpi, mlmodel_render_search, str(e)))

dispatch(RbaRenderOutliers, sys.argv, sys.stdin, sys.stdout, __name__)
