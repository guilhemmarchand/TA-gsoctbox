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

    lower_threshold = Option(
        doc='''
        **Syntax:** **lower_threshold=****
        **Description:** The lower threshold value for the ML model.''',
        require=False, default="0.005", validate=validators.Match("lower_threshold", r"^[\d|\.]*$"))

    upper_threshold = Option(
        doc='''
        **Syntax:** **upper_threshold=****
        **Description:** The upper threshold value for the ML model.''',
        require=False, default="0.005", validate=validators.Match("lower_threshold", r"^[\d|\.]*$"))

    time_factor = Option(
        doc='''
        **Syntax:** **time_factor=****
        **Description:** The time factor value for the ML model.''',
        require=False, default="%w%H", validate=validators.Match("lower_threshold", r"^.*$"))

    earliest_time = Option(
        doc='''
        **Syntax:** **earliest_time=****
        **Description:** The earliest time quantifier for the mstats ML training search.''',
        require=False, default="-90d", validate=validators.Match("earliest_time", r"^.*$"))

    latest_time = Option(
        doc='''
        **Syntax:** **latest_time=****
        **Description:** The latest time quantifier for the mstats ML training search.''',
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

        # Define an header for requests authenticated communications with splunkd
        header = {
            'Authorization': 'Splunk %s' % session_key,
            'Content-Type': 'application/json'}

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

        ################################################
        # Step 2: for each BUNIT, create a model per KPI
        ################################################

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

                    # define the values for the ML models (from default)
                    lower_threshold = self.lower_threshold
                    upper_threshold = self.upper_threshold
                    time_factor = self.time_factor
                    earliest_time = self.earliest_time
                    latest_time = self.latest_time

                    new_kvrecord = {
                        "bunit": bunit,
                        "kpi": kpi,
                        "lower_threshold": self.lower_threshold,
                        "upper_threshold": self.upper_threshold,
                        "time_factor": self.time_factor,
                        "earliest_time": self.earliest_time,
                        "latest_time": self.latest_time,
                        "last_exec": "pending",
                        "last_status": "pending",
                        "last_results_count": "pending",
                        "last_message": "pending",
                        "modelid": "pending",
                    }

                    collection.data.insert(json.dumps(new_kvrecord))
                    logging.info("successfully inserted the new bunit record in the KVstore, record=\"{}\"".format(json.dumps(new_kvrecord, indent=4)))

                else:

                    try:

                        # get the values from the KVstore
                        lower_threshold = kvrecord.get('lower_threshold')
                        upper_threshold = kvrecord.get('uper_threshold')
                        time_factor = kvrecord.get('time_factor')
                        earliest_time = kvrecord.get('earliest_time')
                        latest_time = kvrecord.get('latest_time')

                        # log
                        logging.info("successfully loaded the bunit configuration from record=\"{}\"".format(json.dumps(kvrecord, indent=2)))

                    except Exception as e:

                        # fallback to default values
                        lower_threshold = self.lower_threshold
                        upper_threshold = self.upper_threshold
                        time_factor = self.time_factor
                        earliest_time = self.earliest_time
                        latest_time = self.latest_time

                        # log
                        logging.error("failure to retrieve values from the KVstore record=\"{}\" with exception=\"{}\"".format(json.dumps(kvrecord, indent=2), str(e)))

                # define:

                # - the name of model id (extract the second segment of the metric_name)
                modelid = "rba_" + str(bunit).replace(" ", "_").replace("-", "_").lower() + "_" + kpi.split(".")[1]

                # set the lookup name
                ml_model_lookup_name = "__mlspl_" + modelid + ".mlmodel"

                # if the file exists already in the app directory, it needs to be purged from a REST call
                if os.path.exists(os.path.join(splunkhome, 'etc', 'apps', self.app, 'lookups', ml_model_lookup_name)):

                    # Attempt to delete the current ml model
                    rest_url = 'https://localhost:' + str(splunkd_port) \
                                + '/servicesNS/' + str(username) + '/' + self.app + '/data/lookup-table-files/' + str(ml_model_lookup_name)

                    logging.info("attempting to delete Machine Learning lookup_name=\"{}\"".format(ml_model_lookup_name))
                    try:
                        response = requests.delete(rest_url, headers=header, verify=False)
                        if response.status_code not in (200, 201, 204):
                            logging.error("failure to delete ML lookup_name=\"{}\", url=\"{}\", response.status_code=\"{}\", response.text=\"{}\"".format(ml_model_lookup_name, rest_url, response.status_code, response.text))
                        else:                                    
                            logging.info("action=\"success\", deleted lookup_name=\"{}\" successfully".format(ml_model_lookup_name))

                    except Exception as e:
                        logging.error("failure to delete ML lookup_name=\"{}\" with exception:\"{}\"".format(ml_model_lookup_name, str(e)))

                # - the search logic that generates and train the ML model

                mlmodel_gen_search = "| mstats avg(rba.cummulative_risk_score) as rba.cummulative_risk_score where index=security_siem_metrics " +\
                    "risk_object_bunit=\"" + bunit.replace("|", "\\|") + "\" by risk_object_bunit span=1h" +\
                    "\n| eval factor=strftime(_time, \"" + time_factor + "\")" +\
                    "\n| fit DensityFunction rba.cummulative_risk_score lower_threshold=" + lower_threshold + " upper_threshold=" + upper_threshold + " into " + modelid  + " by factor" +\
                    "\n| rex field=BoundaryRanges \"(-Infinity:(?<LowerBound>[\d|\.]*))|((?<UpperBound>[\d|\.]*):Infinity)\"" +\
                    "\n| foreach LowerBound UpperBound [ eval <<FIELD>> = if(isnum('<<FIELD>>'), '<<FIELD>>', 0) ]" +\
                    "\n| fields _time rba.cummulative_risk_score LowerBound UpperBound"

                # set kwargs
                kwargs = {
                                    "earliest_time": earliest_time,
                                    "latest_time": latest_time,
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

                    # handle permissions if we have results
                    if results_count>0:

                        # Handle permissions and sharing for the ML model lookup
                        logging.info("attempting to update permissions of Machine Learning lookup_name=\"{}\"".format(ml_model_lookup_name))

                        rest_url = 'https://localhost:' + str(splunkd_port) \
                                    + '/servicesNS/' + str(username) + '/' + self.app + '/data/lookup-table-files/' + str(ml_model_lookup_name) + "/acl"

                        try:
                            response = requests.post(rest_url, headers=header, data={'owner' : self.owner, 'sharing' : 'global', 'perms.write' : 'admin', 'perms.read' : '*'},
                                                verify=False)
                            if response.status_code not in (200, 201, 204):
                                logging.error("failure to update ML permissions lookup_name=\"{}\", url=\"{}\", response.status_code=\"{}\", response.text=\"{}\"".format(ml_model_lookup_name, rest_url, response.status_code, response.text))
                            else:                                    
                                logging.info("action=\"success\", permissions of lookup_name=\"{}\" were updated successfully".format(ml_model_lookup_name))

                        except Exception as e:
                            logging.error("failure to update ML permissions lookup_name=\"{}\" with exception:\"{}\"".format(ml_model_lookup_name, str(e)))

                    # yield results
                    yield_record = {
                        '_time': time.time(),
                        'action': 'success',
                        'bunit': bunit,
                        'kpi': kpi,
                        'modelid': ml_model_lookup_name,
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

                    # Insert the last execution, and the status in the KVstore record
                    try:
                        current_kvrecord = collection.data.query(query=(json.dumps(query_string)))[0]
                        current_key = current_kvrecord.get('_key')

                        # update or add our Metadata
                        current_kvrecord['last_exec'] = time.time()
                        current_kvrecord['last_status'] = 'success'
                        current_kvrecord['last_results_count'] = results_count
                        current_kvrecord['last_message'] = "Machine Leaning Model ml_model_lookup_name=\"{}\" was processed successfully".format(ml_model_lookup_name)
                        current_kvrecord['modelid'] = ml_model_lookup_name
                        collection.data.update(str(current_key), json.dumps(current_kvrecord))

                    except Exception as e:
                        logging.error("failure to update the KVstore and add execution Metadata, exception=\"{}\"".format(str(e)))

                #
                # ML gen terminated for that entity / kpi
                #

                except Exception as e:
                    logging.error("failed to run the bunit ML model train search with exception=\"{}\"".format(str(e)))

                    # yield results
                    yield_record = {
                        '_time': time.time(),
                        'action': 'failure',
                        'exception': str(e),
                        'bunit': bunit,
                        'kpi': kpi,
                        'modelid': ml_model_lookup_name,
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

                    # Insert the last execution, and the status in the KVstore record
                    try:
                        current_kvrecord = collection.data.query(query=(json.dumps(query_string)))[0]
                        current_key = current_kvrecord.get('_key')

                        # update or add our Metadata
                        current_kvrecord['last_exec'] = time.time()
                        current_kvrecord['last_status'] = 'failure'
                        current_kvrecord['last_results_count'] = 0
                        current_kvrecord['last_message'] = "Machine Leaning Model ml_model_lookup_name=\"{}\" training has failed, exception=\{}\"".format(ml_model_lookup_name, str(e))
                        current_kvrecord['modelid'] = ml_model_lookup_name
                        collection.data.update(str(current_key), json.dumps(current_kvrecord))

                    except Exception as e:
                        logging.error("failure to update the KVstore and add execution Metadata, exception=\"{}\"".format(str(e)))

dispatch(RbaGenModels, sys.argv, sys.stdin, sys.stdout, __name__)
