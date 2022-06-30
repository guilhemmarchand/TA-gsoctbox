#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals
from distutils.ccompiler import new_compiler

__author__ = "Guilhem Marchand"
__version__ = "0.1.0"
__status__ = "PRODUCTION"

import os
import sys
import logging
import splunk
import splunk.entity
import time
import json
import re
from collections import OrderedDict
import ast
from requests.auth import HTTPBasicAuth
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ['SPLUNK_HOME']

# set logging
filehandler = logging.FileHandler(splunkhome + "/var/log/splunk/gsoctbox_riskmvlookup.log", 'a')
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
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
from splunklib import six
import splunklib.client as client
import splunklib.results as results

@Configuration()
class RiskMvLookup(StreamingCommand):

    source_field = Option(
        doc='''
        **Syntax:** **The source field=****
        **Description:** source field.''',
        require=True, validate=validators.Match("source_field", r"^.*$"))

    # status will be statically defined as imported

    def stream(self, records):

        # set loglevel
        loglevel = 'INFO'

        # If fails, don't break
        try:
            conf_file = "ta_gsoctbox_settings"
            confs = self.service.confs[str(conf_file)]
            for stanza in confs:
                if stanza.name == 'logging':
                    for stanzakey, stanzavalue in stanza.content.items():
                        if stanzakey == "loglevel":
                            loglevel = stanzavalue
            logginglevel = logging.getLevelName(loglevel)
            log.setLevel(logginglevel)

        except Exception as e:
            logging.warning("Failed to retrieve the logging level from application level configuration with exception=\"{}\"")
            log.setLevel(loglevel)

        # performance counter
        start = time.time()

        # Get the session key
        session_key = self._metadata.searchinfo.session_key

        # Get splunkd port
        try:
            splunkd_port_search = re.search(':(\d+)$', self._metadata.searchinfo.splunkd_uri, re.IGNORECASE)
            if splunkd_port_search:
                splunkd_port = splunkd_port_search.group(1)
                logging.debug("splunkd_port=\"{}\" extracted successfully from splunkd_uri=\"{}\"".format(splunkd_port, self._metadata.searchinfo.splunkd_uri))
        except Exception as e:
            logging.error("Failed to extract splunkd_port from splunkd_uri with exception=\"{}\"".format(e))
            splunkd_port = "8089"

        # Get service
        service = client.connect(
            owner="nobody",
            app="TA-gsoctbox",
            port=splunkd_port,
            token=session_key
        )

        # Loop in the results
        for record in records:

            # Our final record dict
            final_record = {}

            # In a future version, we could potentially accept a list of fields in input?
            source_fields = [ self.source_field ]
            logging.debug("source_fields=\"{}\"".format(source_fields))

            # loop through the list
            for source_field in source_fields:

                # define a target_field
                target_field_name = "risk_" + str(source_field)
                target_field_ci_name = "risk_" + str(source_field) + "_ci"

                # if we have the request field, proceed, otherwise render
                record_has_target = False

                # Set the default boolean
                target_is_list = False

                # try getting a value
                try:
                    source_field_value = record[source_field]
                    logging.debug("command=\"riskmvlookup\", source_field=\"{}\"".format(source_field_value))
                    record_has_target = True

                except Exception as e:
                     logging.debug("command=\"riskmvlookup\", source_field=\"{}\" was not found")
                     record_has_target = False

                # proceed if we have a value
                if record_has_target:

                    source_field_value = record[source_field]
                    logging.debug("command=\"riskmvlookup\", source_field=\"{}\"".format(source_field_value))

                    # only perform this operation is the field is a multivalue field
                    # otherwise, we render the upstream results downstream as it came

                    if type(source_field_value) == list:
                        logging.info("command=\"riskmvlookup\", detected multivalue format, source_field_value=\"{}\" is a list".format(source_field_value))

                        # Set true
                        target_is_list = True

                        # do the enrichment

                        splQuery = "| makeresults | eval " + str(source_field) + "=\""
                        # loop through the list

                        for subEntity in source_field_value:
                            splQuery = splQuery + str(subEntity) + "|"
                        # close
                        splQuery = splQuery + "\" | makemv delim=\"|\" " + str(source_field)

                        # get the cim_entity_zone
                        try:
                            cim_entity_zone = record['cim_entity_zone']
                        except Exception as e:
                            cim_entity_zone = "unknown"
                            logging.error("There is no cim_entity_zone in the upstream result, record=\"{}\"".format(json.dumps(record)))

                        # enrich
                        splQuery = splQuery + "| mvexpand " + str(source_field) +\
                            " | eval cim_entity_zone=\"" + str(cim_entity_zone) + "\"" +\
                            " | `get_asset_zone(" + str(source_field) + ")`" + " | `get_asset(" + str(source_field) + ")`"

                        # replacement logic
                        splQuery = splQuery + " | rex field=" + str(source_field) + "_asset \"(?<risk_" + str(source_field) + "_ci>ci\w+)\"" +\
                            " | eval risk_" + str(source_field) + " = coalesce(risk_" + str(source_field) + "_ci, " + str(source_field) + ") " +\
                            " | eval " + str(source_field) + " = coalesce(" + str(source_field) + "_ci, " + str(source_field) + ") " +\
                            " | stats values(risk*) as \"risk*\""
                        logging.debug("splQuery=\"{}\"".format(splQuery))

                        # run the search
                        kwargs_search = {"app": "TA-gsoctbox", "earliest_time": "-5m", "latest_time": "now"}

                        # shall the search fail for some reasons, do not impact anything and render the original results
                        try:

                            # spawn the search and get the results
                            searchresults = service.jobs.oneshot(splQuery, **kwargs_search)

                            # loop through the results
                            reader = results.ResultsReader(searchresults)
                            for item in reader:
                                query_result = item
                            logging.debug("splQuery was successful, result=\"{}\"".format(json.dumps(query_result, indent=0)))

                            # Add to our new record
                            try:
                                # attempt extract target
                                target_field_value = query_result[str(target_field_name)]
                                logging.debug("target_field=\"{}\"".format(target_field_value))
                                final_record[str(target_field_name)] = target_field_value
                            except Exception as e:
                                logging.info("No value for field=\"{}\" to be extracted".format(target_field_name))

                            try:
                                # attempt extract target
                                target_field_ci_value = query_result[target_field_ci_name]
                                logging.debug("target_field_ci=\"{}\"".format(target_field_ci_value))
                                final_record[str(target_field_ci_name)] = target_field_ci_value
                            except Exception as e:
                                logging.info("No value for field=\"{}\" to be extracted".format(target_field_ci_name))

                        except Exception as e:
                            logging.error("splQuery has failed with exception=\"{}\"".format(e))

                            # these fields are single values, do not change anything
                            try:
                                target_field_value = record[str(target_field_name)]
                                final_record[str(target_field_name)] = target_field_value
                            except Exception as e:
                                logging.info("No value for field=\"{}\" to be extracted".format(target_field_name))

                            try:
                                target_field_ci_value = record[str(target_field_ci_name)]
                                final_record[str(target_field_ci_name)] = target_field_ci_value
                            except Exception as e:
                                logging.info("No value for field=\"{}\" to be extracted".format(target_field_ci_name))

                    else:
                        logging.debug("source_field_value=\"{}\" is not a list, nothing to do.".format(source_field_value))
                        # these fields are single values, do not change anything
                        target_is_list = False

                    # Add all other fields from the original except those

                    # get time, if any
                    time_value = None
                    try:
                        time_value = record['_time']
                    except Exception as e:
                        time_value = None

                    # loop through the dict
                    for k in record:

                        if target_is_list:
                            # if not our input field, and not _time
                            if k != '_time' and k != target_field_name and k!= target_field_ci_name:
                                final_record[k] = record[k]
                        else:
                            # if not our input field, and not _time
                            if k != '_time':
                                final_record[k] = record[k]

                    # if time was defined, add it
                    if time_value:
                        final_record['_time'] = record['_time']

                    # yield
                    logging.debug("final_record=\"{}\"".format(final_record))
                    yield final_record

                # else render everything as per the original record
                else:

                    # get time, if any
                    time_value = None
                    try:
                        time_value = record['_time']
                    except Exception as e:
                        time_value = None

                    # loop through the dict
                    for k in record:

                        # if not our input field, and not _time
                        if k != '_time':
                            final_record[k] = record[k]

                    # if time was defined, add it
                    if time_value:
                        final_record['_time'] = record['_time']

                    # yield
                    logging.debug("final_record=\"{}\"".format(final_record))
                    yield final_record

        # end
        logging.info("command=riskmvlookup, process terminated, duration_sec=\"{}\"".format(str(time.time()-start)))

dispatch(RiskMvLookup, sys.argv, sys.stdin, sys.stdout, __name__)
