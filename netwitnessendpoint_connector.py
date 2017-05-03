# --
# File: netwitnessendpoint/netwitnessendpoint_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --

# Standard library imports
import json
import hashlib
import requests

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Local imports
import netwitnessendpoint_consts as consts

# Dictionary containing details of possible HTTP error codes in API Response
ERROR_RESPONSE_DICT = {
    consts.NWENDPOINT_REST_RESP_UNAUTHORIZED: consts.NWENDPOINT_REST_RESP_UNAUTHORIZED_MSG,
    consts.NWENDPOINT_REST_REQUEST_BINDING_EXCEPTION: consts.NWENDPOINT_REST_REQUEST_BINDING_EXCEPTION_MSG,
    consts.NWENDPOINT_REST_INVALID_PERMISSION: consts.NWENDPOINT_REST_INVALID_PERMISSION_MSG,
    consts.NWENDPOINT_REST_RESOURCE_NOT_FOUND: consts.NWENDPOINT_REST_RESOURCE_NOT_FOUND_MSG
}


class NetwitnessendpointConnector(BaseConnector):
    """ This is an AppConnector class that inherits the BaseConnector class. It implements various actions supported by
    NetWitness Endpoint and helper methods required to run the actions.
    """

    def __init__(self):

        # Calling the BaseConnector's init function
        super(NetwitnessendpointConnector, self).__init__()
        self._url = None
        self._username = None
        self._password = None
        self._verify_server_cert = None
        self._max_ioc_level = None
        self._app_state = dict()

        return

    def initialize(self):
        """ This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """

        config = self.get_config()
        self._url = config[consts.NWENDPOINT_CONFIG_URL].strip('/')
        self._username = config[consts.NWENDPOINT_CONFIG_USERNAME]
        self._password = config[consts.NWENDPOINT_CONFIG_PASSWORD]
        self._verify_server_cert = config.get(consts.NWENDPOINT_CONFIG_VERIFY_SSL, False)
        self._max_ioc_level = int(config.get(consts.NWENDPOINT_CONFIG_MAX_IOC_LEVEL,
                                             consts.NWENDPOINT_DEFAULT_IOC_LEVEL))

        # load the state of app stored in JSON file
        self._app_state = self.load_state()

        return phantom.APP_SUCCESS

    def _make_rest_call(self, endpoint, action_result, params=None, data=None, method="post", timeout=None):
        """ Function that makes the REST call to the device. It is a generic function that can be called from various
        action handlers.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param params: request parameters if method is GET
        :param data: request body
        :param method: GET/POST/PUT/DELETE (default=POST)
        :return: status success/failure(along with appropriate message), response obtained by making an API call
        """

        response_data = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            self.debug_print(consts.NWENDPOINT_ERR_API_UNSUPPORTED_METHOD.format(method=method))
            # set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(
                phantom.APP_ERROR, consts.NWENDPOINT_ERR_API_UNSUPPORTED_METHOD.format(method=method)), response_data
        except Exception as e:
            self.debug_print(consts.NWENDPOINT_EXCEPTION_OCCURRED, e)
            # set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, consts.NWENDPOINT_EXCEPTION_OCCURRED, e), response_data

        # Make the call
        try:
            if timeout is not None:
                response = request_func("{}{}".format(self._url, endpoint), data=data, params=params,
                                        auth=(self._username, self._password), verify=self._verify_server_cert,
                                        timeout=timeout)
            else:
                response = request_func("{}{}".format(self._url, endpoint), data=data, params=params,
                                        auth=(self._username, self._password), verify=self._verify_server_cert)
        except Exception as e:
            self.debug_print(consts.NWENDPOINT_ERR_SERVER_CONNECTION, e)
            # set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, consts.NWENDPOINT_ERR_SERVER_CONNECTION, e), \
                   response_data

        # Try parsing the json
        try:
            content_type = response.headers.get('content-type')
            if content_type and content_type.find('json') != -1:
                response_data = response.json()
            else:
                response_data = response.text
        except Exception as e:
            # r.text is guaranteed to be NON None, it will be empty, but not None
            msg_string = consts.NWENDPOINT_ERR_JSON_PARSE.format(raw_text=response.text)
            self.debug_print(msg_string, e)
            # set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, msg_string, e), response_data

        if response.status_code in ERROR_RESPONSE_DICT:
            message = ERROR_RESPONSE_DICT[response.status_code]

            # overriding message if available in response
            if isinstance(response_data, dict):
                message = response_data.get("ResponseStatus", {}).get("Message", message)

            self.debug_print(consts.NWENDPOINT_ERR_FROM_SERVER.format(status=response.status_code, detail=message))
            # set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, consts.NWENDPOINT_ERR_FROM_SERVER,
                                            status=response.status_code, detail=message), response_data
        # In case of success scenario
        if response.status_code == consts.NWENDPOINT_REST_RESP_SUCCESS:
            response_data = {
                consts.NWENDPOINT_REST_RESPONSE: response_data,
                consts.NWENDPOINT_REST_RESPONSE_HEADERS: response.headers
            }
            return phantom.APP_SUCCESS, response_data

        # If response code is unknown
        self.debug_print(consts.NWENDPOINT_ERR_FROM_SERVER.format(status=response.status_code,
                                                                  detail=consts.NWENDPOINT_REST_RESP_OTHER_ERROR_MSG))
        # All other response codes from REST call
        # Set the action_result status to error, the handler function will most probably return as is
        return action_result.set_status(phantom.APP_ERROR, consts.NWENDPOINT_ERR_FROM_SERVER,
                                        status=response.status_code,
                                        detail=consts.NWENDPOINT_REST_RESP_OTHER_ERROR_MSG), response_data

    def _paginate_response_data(self, endpoint, action_result, key, params=None, limit=None):
        """ Helper function to get paginated data of specified GET API. If limit parameter is not provided, all page's
        data will be fetched.

        :param endpoint: Endpoint to get data
        :param action_result: object of ActionResult class
        :param key: response key that contains response list
        :param params: request parameters
        :param limit: maximum number of records to fetch
        :return: status (success/failure) and (list containing data fetched or empty list)
        """

        return_list = []

        if params:
            params["page"] = 1
        else:
            params = {"page": 1}

        # If limit is not provided, then default value of limit will be considered
        if not limit or limit == "0":
            limit = consts.NWENDPOINT_DEFAULT_LIMIT
            limit_provided = False
        else:
            limit = int(limit)
            # If limit is less than default value of limit, then querying only specified amount of data
            # for the provided machine
            if limit < consts.NWENDPOINT_DEFAULT_LIMIT:
                params["per_page"] = limit
            limit_provided = True

        # Variable that will be used to fetch specific amount of information from the response
        pending_data_length = limit

        while True:
            # Making the call
            response_status, response = self._make_rest_call(endpoint, action_result, params=params, method="get")

            # Something went wrong
            if phantom.is_fail(response_status):
                return action_result.get_status(), None

            if response[consts.NWENDPOINT_REST_RESPONSE].get(key):
                return_list += response[consts.NWENDPOINT_REST_RESPONSE][key][:pending_data_length]

            if limit_provided:
                if len(return_list) == limit:
                    break

                # next expected amount of information to fetch from the response
                pending_data_length -= consts.NWENDPOINT_DEFAULT_LIMIT

            params["page"] += 1

            if response[consts.NWENDPOINT_REST_RESPONSE_HEADERS].get("Link", "").find('rel="next",') == -1:
                break

        return phantom.APP_SUCCESS, return_list

    def _blacklist_domain(self, param):
        """ Function used to blacklist given domain.

        :param param: dictionary of input parameters
        :return: status status/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param[consts.NWENDPOINT_JSON_DOMAIN]

        # Convert URL to domain
        if phantom.is_url(domain):
            domain = phantom.get_host_from_url(domain)

        # Get mandatory parameter
        payload = {'Domains': [domain]}

        # Make the call
        return_val, response = self._make_rest_call(consts.NWENDPOINT_BLACKLIST_DOMAIN_ENDPOINT, action_result,
                                                    data=payload)

        # Something went wrong
        if phantom.is_fail(return_val):
            return action_result.get_status()

        # Changing response to make it eligible for contextual actions
        response = {"domain": response[consts.NWENDPOINT_REST_RESPONSE]["Domains"][0]}
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, consts.NWENDPOINT_BLACKLIST_DOMAIN_SUCCESS)

    def _blacklist_ip(self, param):
        """ Function used to blacklist given IP.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get mandatory input parameters
        payload = {"Ips": [param[consts.NWENDPOINT_JSON_IP_ADDRESS]]}

        # Make the call
        ret_value, response = self._make_rest_call(consts.NWENDPOINT_BLOCK_IP_ENDPOINT, action_result=action_result,
                                                   data=payload)

        # something went wrong
        if phantom.is_fail(ret_value):
            return action_result.get_status()

        response = {"ip": response[consts.NWENDPOINT_REST_RESPONSE]["Ips"][0]}
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, consts.NWENDPOINT_BLACKLIST_IP_SUCCESS)

    def _list_endpoints(self, param):
        """ Function used to get list of all endpoints configured on RSA NetWitness Endpoint.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Get optional parameters
        ioc_score_gte = param.get(consts.NWENDPOINT_JSON_IOC_SCORE_GTE)
        ioc_score_lte = param.get(consts.NWENDPOINT_JSON_IOC_SCORE_LTE)
        limit = param.get(consts.NWENDPOINT_JSON_LIMIT)

        # Prepare dictionary of optional parameters
        params = {}

        # Validate that ioc_score_gte is positive integer if provided and update params dict
        if ioc_score_gte:
            if ioc_score_gte.isdigit():
                params[consts.NWENDPOINT_JSON_IOC_SCORE_GTE] = int(ioc_score_gte)
            else:
                self.debug_print(consts.NWENDPOINT_JSON_IOC_SCORE_PARAM_ERROR)
                return action_result.set_status(phantom.APP_ERROR, consts.NWENDPOINT_JSON_IOC_SCORE_PARAM_ERROR)

        # Validate that ioc_score_lte is positive integer if provided and update params dict
        if ioc_score_lte:
            if ioc_score_lte.isdigit():
                params[consts.NWENDPOINT_JSON_IOC_SCORE_LTE] = int(ioc_score_lte)
            else:
                self.debug_print(consts.NWENDPOINT_JSON_IOC_SCORE_PARAM_ERROR)
                return action_result.set_status(phantom.APP_ERROR, consts.NWENDPOINT_JSON_IOC_SCORE_PARAM_ERROR)

        # Validate that limit is positive integer if provided and update params dict
        if limit:
            if limit.isdigit():
                ret_value, response = self._paginate_response_data(consts.NWENDPOINT_LIST_MACHINES_ENDPOINT,
                                                                   action_result, "Items", params=param,
                                                                   limit=limit)
            else:
                self.debug_print(consts.NWENDPOINT_JSON_INVALID_LIMIT)
                return action_result.set_status(phantom.APP_ERROR, consts.NWENDPOINT_JSON_INVALID_LIMIT)
        else:
            ret_value, response = self._paginate_response_data(consts.NWENDPOINT_LIST_MACHINES_ENDPOINT, action_result,
                                                               "Items", params=param)
        # Something went wrong
        if phantom.is_fail(ret_value):
            return action_result.get_status()

        # Update summary data
        summary_data['total_endpoints'] = len(response)

        # replicating API response by adding key to list
        action_result.add_data({"Items": response})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_system_info(self, param):
        """ Function used to get endpoint's information from given endpoint's guid.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Get mandatory parameter
        guid = param[consts.NWENDPOINT_JSON_GUID]

        # Make the call
        return_val, response = self._make_rest_call(
            consts.NWENDPOINT_GET_SYSTEM_INFO_ENDPOINT.format(guid), action_result, method="get")

        # Something went wrong
        if phantom.is_fail(return_val):
            return action_result.get_status()

        action_result.add_data(response[consts.NWENDPOINT_REST_RESPONSE])

        # Update summary data
        summary_data['machine_name'] = response[consts.NWENDPOINT_REST_RESPONSE]['Machine']['MachineName']
        summary_data['iiocscore'] = response[consts.NWENDPOINT_REST_RESPONSE]['Machine']['IIOCScore']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _scan_endpoint(self, param):
        """ Function used to request scan of an endpoint.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get mandatory parameter
        guid = param[consts.NWENDPOINT_JSON_GUID]

        # Get optional parameters
        filter_hooks = param.get(consts.NWENDPOINT_JSON_FILTER_HOOKS)
        cpu_max = param.get(consts.NWENDPOINT_JSON_CPUMAX)
        cpu_max_vm = param.get(consts.NWENDPOINT_JSON_CPUMAXVM)
        cpu_min = param.get(consts.NWENDPOINT_JSON_CPUMIN)

        # Prepare request parameters
        payload = {"Guid": guid}

        # Update request data according to value of filter_hooks
        if filter_hooks == "Signed Modules":
            payload['FilterSigned'] = True
        elif filter_hooks == "Whitelisted Certificates":
            payload['FilterTrustedRoot'] = True

        # Validate that cpu_max is positive integer and update the request parameters
        if cpu_max:
            if cpu_max.isdigit():
                payload["CpuMax"] = int(cpu_max)
            else:
                self.debug_print(consts.NWENDPOINT_JSON_CPU_MAX_ERROR)
                return action_result.set_status(phantom.APP_ERROR, consts.NWENDPOINT_JSON_CPU_MAX_ERROR)

        # Validate that cpu_max is positive integer and update the request parameters
        if cpu_max_vm:
            if cpu_max_vm.isdigit():
                payload["CpuMaxVm"] = int(cpu_max_vm)
            else:
                self.debug_print(consts.NWENDPOINT_JSON_CPU_MAX_VM_ERROR)
                return action_result.set_status(phantom.APP_ERROR, consts.NWENDPOINT_JSON_CPU_MAX_VM_ERROR)

        # Validate that cpu_min is positive integer and update the request parameters
        if cpu_min:
            if cpu_min.isdigit():
                payload["CpuMin"] = int(cpu_min)
            else:
                self.debug_print(consts.NWENDPOINT_JSON_CPU_MIN_ERROR)
                return action_result.set_status(phantom.APP_ERROR, consts.NWENDPOINT_JSON_CPU_MIN_ERROR)

        optional_params_dict = {"ScanCategory": param.get(consts.NWENDPOINT_JSON_SCAN_CATEGORY),
                                "CaptureFloatingCode": param.get(consts.NWENDPOINT_JSON_CAPTURE_FLOATING_CODE),
                                "AllNetworkConnections": param.get(consts.NWENDPOINT_JSON_ALL_NETWORK_CONNECTIONS),
                                "ResetAgentNetworkCache": param.get(
                                    consts.NWENDPOINT_JSON_RESET_AGENT_NETWORK_CACHE),
                                "RetrieveMasterBootRecord": param.get(
                                    consts.NWENDPOINT_JSON_RETRIEVE_MASTER_BOOT_RECORD),
                                "Notify": param.get(consts.NWENDPOINT_JSON_NOTIFY)}

        # Prepare parameters dictionary from optional_params_dict by eliminating keys having None value
        optional_params_dict = dict((key, value) for key, value in optional_params_dict.iteritems() if value)

        # Update request parameters
        payload.update(optional_params_dict)

        # Make the call
        return_val, res = self._make_rest_call(consts.NWENDPOINT_SCAN_ENDPOINT.format(guid), action_result,
                                               data=payload)

        # Something went wrong
        if phantom.is_fail(return_val):
            return action_result.get_status()

        action_result.add_data(res[consts.NWENDPOINT_REST_RESPONSE])

        return action_result.set_status(phantom.APP_SUCCESS, consts.NWENDPOINT_SCAN_ENDPOINT_MESSAGE)

    def _get_scan_data(self, param):
        """ Function used to get scanned data of endpoint.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # List of scan categories for which we need to fetch data
        type_mappings = ["Services", 'Processes', "Dlls", "Drivers", "AutoRuns", "Tasks", "ImageHooks", "KernelHooks",
                         "WindowsHooks", "SuspiciousThreads", "RegistryDiscrepencies", "Network", "Tracking"]

        # Get mandatory parameter
        guid = param[consts.NWENDPOINT_JSON_GUID]

        # Get optional parameter
        limit = param.get(consts.NWENDPOINT_JSON_LIMIT)

        # Validate that limit is positive integer
        if limit:
            if not limit.isdigit():
                self.debug_print(consts.NWENDPOINT_JSON_INVALID_LIMIT)
                return action_result.set_status(phantom.APP_ERROR, consts.NWENDPOINT_JSON_INVALID_LIMIT)

        data = {}

        # Iterate over each scan category and fetch corresponding data
        for value in type_mappings:

            self.send_progress("Getting data for {}".format(value))

            # Get data for scan category
            ret_value, response = self._paginate_response_data(
                consts.NWENDPOINT_GET_SCAN_DATA_ENDPOINT.format(guid, value.lower()), action_result, value, limit=limit)

            # Something went wrong
            if phantom.is_fail(ret_value):
                return action_result.get_status()

            data[value] = response

        action_result.add_data(data)

        # Update summary data according to scanned data categories
        for data_key, value in data.items():
            summary_data[data_key.lower()] = len(value)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _create_dict_hash(self, input_dict):
        """ Function used to create hash of the given input dictionary.

        :param input_dict: dictionary for which we need to generate hash
        :return: MD5 hash
        """

        input_dict_str = None

        if not input_dict:
            return None

        try:
            input_dict_str = json.dumps(input_dict, sort_keys=True)
        except Exception as e:
            print str(e)
            self.debug_print('Handled exception in _create_dict_hash', e)
            return None

        return hashlib.md5(input_dict_str).hexdigest()

    def _get_ioc(self, param):
        """ Get IOC detail.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # get mandatory input parameter
        name = param[consts.NWENDPOINT_JSON_NAME]

        # get details of IOC
        ret_value, response = self._make_rest_call(consts.NWENDPOINT_GET_IOC_ENDPOINT.format(name), action_result,
                                                   method="get")

        # something went wrong
        if phantom.is_fail(ret_value):
            return action_result.get_status()

        ioc_query = response[consts.NWENDPOINT_REST_RESPONSE]['iocQuery']

        # If IOC is not available on server it will return empty dictionary
        if not ioc_query:
            self.debug_print(consts.NWENDPOINT_ERROR_IOC_QUERY_NOT_EXIST)
            return action_result.set_status(phantom.APP_ERROR, consts.NWENDPOINT_ERROR_IOC_QUERY_NOT_EXIST)

        summary_data['ioc_level'] = ioc_query['IOCLevel']

        # get machines of particular IOC
        ret_value, machines = self._paginate_response_data(consts.NWENDPOINT_GET_IOC_MACHINES_ENDPOINT.format(name),
                                                           action_result, "iocMachines")

        if phantom.is_fail(ret_value):
            return action_result.get_status()

        # maintaining modules that are categorized in given IOC
        ioc_module = []

        # for each machines in IOC get all modules of that machine
        for machine in machines:
            machine_id = machine['AgentID']
            self.send_progress("Getting modules for machine {}".format(machine_id))

            # Get modules whose IOC score is greater than 1
            params = {'iocscore_gte': 1}

            ret_value, modules = self._paginate_response_data(
                consts.NWENDPOINT_MACHINES_MODULES_ENDPOINT.format(machine_id), action_result, "Items", params=params)

            if phantom.is_fail(ret_value):
                return action_result.get_status()

            # for each module get IOCs in which it is categorized
            for machine_module in modules:
                module_id = machine_module['Id']

                ret_value, module_iocs = self._paginate_response_data(
                    consts.NWENDPOINT_MACHINES_MODULES_INSTANTIOCS_ENDPOINT.format(machine_id, module_id),
                    action_result, "Iocs")

                if phantom.is_fail(ret_value):
                    return action_result.get_status()

                # if module belongs to given IOC, add it into the list
                ioc_module += [ioc for ioc in module_iocs if ioc['IOCName'] == name]

        # Adding details of IOC, its machines and modules in action result
        response = {"iocQuery": ioc_query, "iocMachines": machines, "iocModules": ioc_module}

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_processes(self, param):
        """ Function used to get processes of an endpoint.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Get mandatory parameter
        guid = param[consts.NWENDPOINT_JSON_GUID]

        # Get optional parameter
        limit = param.get(consts.NWENDPOINT_JSON_LIMIT)

        # Validate that limit is positive integer
        if limit:
            if not limit.isdigit():
                self.debug_print(consts.NWENDPOINT_JSON_INVALID_LIMIT)
                return action_result.set_status(phantom.APP_ERROR, consts.NWENDPOINT_JSON_INVALID_LIMIT)

        # Get processes
        ret_value, response = self._paginate_response_data(
            consts.NWENDPOINT_GET_SCAN_DATA_ENDPOINT.format(guid, 'processes'), action_result, "Processes", limit=limit)

        # Something went wrong
        if phantom.is_fail(ret_value):
            return action_result.get_status()

        # Update summary data and add response in action_result
        summary_data['total_processes'] = len(response)
        action_result.add_data({"Processes": response})

        return action_result.set_status(phantom.APP_SUCCESS)

    def ingest_data(self, ioc_query_list):
        """ Function used to create containers and artifacts from the provided ioc_query_list.

        :param ioc_query_list: list of ioc queries and corresponding machine and modules(files) information using which
        we need to prepare container and artifacts.
        """

        # mapping for endpoint related artifacts
        machine_artifacts_mappings = {
            "LocalIP": {"cef": "sourceAddress", "cef_types": ["ip"]},
            "RemoteIP": {"cef": "remoteAddress", "cef_types": ["ip"]},
            "MAC": {"cef": "sourceMacAddress", "cef_types": ["mac address"]},
            "MachineGUID": {"cef": "nweMachineGuid", "cef_types": ["nwe machine guid"]},
            "UserName": {"cef": "sourceUserName", "cef_types": ["user name"]}
        }

        # mapping for files related artifacts
        module_artifacts_mappings = {
            "MD5": {"cef": "fileHashMd5", "cef_types": ["hash", "md5"]},
            "SHA1": {"cef": "fileHashSha1", "cef_types": ["hash", "sha1"]},
            "SHA256": {"cef": "fileHashSha256", "cef_types": ["hash", "sha256"]},
            "FileName": {"cef": "fileName", "cef_types": ["file name"]}
        }

        # mapping of IOCScore with severity of artifacts
        phantom_severity_mapping = {"0": "high", "1": "medium", "2": "low", "3": "low"}

        # Creating container for each IOC query and creating its artifacts
        for ioc in ioc_query_list:
            source_data_identifiers = []
            # Creating container
            container = {
                "name": "{}_{}".format(ioc["Name"], ioc["LastExecuted"]),
                "description": ioc["Description"],
                "data": ioc,
                "source_data_identifier": "{}_{}".format(ioc["Name"], ioc["LastExecuted"])
            }

            self.send_progress("Ingesting data for: {}".format(ioc["Name"]))

            ret_value, response, container_id = self.save_container(container)

            # Something went wrong while creating container
            if phantom.is_fail(ret_value):
                self.debug_print(consts.NWENDPOINT_CONTAINER_ERROR, container)
                continue

            # Creating endpoint related artifacts
            for machine in ioc["iocMachines"]:
                cef = {}
                cef_types = {}
                for field, artifact_details in machine_artifacts_mappings.iteritems():
                    # if field value is present
                    if machine.get(field):
                        cef_value = machine[field]

                        cef[artifact_details["cef"]] = cef_value
                        cef_types[artifact_details["cef"]] = artifact_details["cef_types"]

                # if no fields found
                if not cef:
                    continue

                artifact = {
                    "name": "Endpoint Artifact",
                    "description": consts.NWENDPOINT_ARTIFACTS_DESC,
                    "cef_types": cef_types,
                    "cef": cef,
                    "container_id": container_id,
                    "severity": phantom_severity_mapping[ioc["IOCLevel"]],
                }

                # ignoring same artifacts based on hash
                source_data_identifier = self._create_dict_hash(artifact)
                if source_data_identifier in source_data_identifiers:
                    continue

                source_data_identifiers.append(source_data_identifier)

                # The source_data_identifier should be created after all the keys have been set
                artifact['source_data_identifier'] = source_data_identifier
                ret_value, status_string, artifact_id = self.save_artifact(artifact)

                # Something went wrong while creating artifacts
                if phantom.is_fail(ret_value):
                    self.debug_print(status_string, artifact)
                    continue

            # Creating module(file) related artifacts
            for machine_module in ioc["iocModules"]:
                cef = {}
                cef_types = {}

                for field, artifact_details in module_artifacts_mappings.iteritems():
                    # if field value is present
                    if machine_module.get(field):
                        cef_value = machine_module[field]

                        cef[artifact_details["cef"]] = cef_value
                        cef_types[artifact_details["cef"]] = artifact_details["cef_types"]

                # if no fields found
                if not cef:
                    continue

                artifact = {
                    "name": "File Artifact", "description": consts.NWENDPOINT_ARTIFACTS_DESC,
                    "cef_types": cef_types,
                    "cef": cef,
                    "container_id": container_id,
                    "severity": phantom_severity_mapping[ioc["IOCLevel"]],
                }

                # ignoring same artifacts based on hash
                source_data_identifier = self._create_dict_hash(artifact)
                if source_data_identifier in source_data_identifiers:
                    continue

                source_data_identifiers.append(source_data_identifier)

                # The source_data_identifier should be created after all the keys have been set.
                artifact['source_data_identifier'] = source_data_identifier
                ret_value, status_string, artifact_id = self.save_artifact(artifact)

                # Something went wrong while creating artifacts
                if phantom.is_fail(ret_value):
                    self.debug_print(status_string, artifact)
                    continue

            # Adding IIOC details as artifact
            cef = {"instantIocName": ioc["Name"], "lastExecutedTime": ioc["LastExecuted"],
                   "iocLevel": ioc["IOCLevel"], "osType": ioc["Type"]}

            cef_types = {"instantIocName": ["nwe ioc name"]}

            artifact = {
                "name": "Instant IOC Artifact", "description": consts.NWENDPOINT_ARTIFACTS_DESC,
                "cef_types": cef_types,
                "cef": cef,
                "container_id": container_id,
                "run_automation": True
            }
            artifact['source_data_identifier'] = self._create_dict_hash(artifact)
            ret_value, status_string, artifact_id = self.save_artifact(artifact)

            # Something went wrong while creating artifacts
            if phantom.is_fail(ret_value):
                self.debug_print(status_string, artifact)
                continue

    def get_machine_data(self, action_result, ioc_query_list):
        """ Function used to obtain endpoint data for each query in ioc_query_list.

        :param action_result: object of ActionResult class
        :param ioc_query_list: list of ioc queries for which data needs to be fetched
        :return: status success/failure
        """

        machines_modules_ioc = {}
        ioc_level_mapping = {"0": 1024, "1": 128, "2": 8, "3": 1}

        if self.is_poll_now():
            self.save_progress("Ignoring maximum artifact count")

        # Iterate through each IOC query and obtain corresponding machine related information
        for ioc in ioc_query_list:
            query_name = ioc['Name']
            ioc_machines = []

            # Scheduled ingestion
            if not self.is_poll_now():
                # Obtain any saved state if available else create an empty dictionary
                if not self._app_state.get("app_state"):
                    self._app_state["app_state"] = dict()
                saved_app_state = self._app_state.get("app_state")
                # Add data only if the execution time of ioc query is different or if its a new ioc query
                if not (saved_app_state.get(query_name) == ioc["LastExecuted"]):
                    # Get data
                    ret_value, response = self._paginate_response_data(
                        consts.NWENDPOINT_INSTANTIOC_MACHINE_ENDPOINT.format(query_name), action_result, "iocMachines"
                    )
                    # Something went wrong
                    if phantom.is_fail(ret_value):
                        return action_result.get_status()

                    # Update the state of app
                    self._app_state["app_state"][query_name] = ioc["LastExecuted"]
                    ioc_machines = response

            # Poll now
            else:
                # Get data
                ret_value, ioc_machines = self._paginate_response_data(
                    consts.NWENDPOINT_INSTANTIOC_MACHINE_ENDPOINT.format(query_name), action_result, "iocMachines"
                )
                # Something went wrong
                if phantom.is_fail(ret_value):
                    return action_result.get_status()

            if not ioc_machines:
                continue

            ioc['iocMachines'] = ioc_machines
            ioc['iocModules'] = []

            # get modules of machines
            for ioc_machine in ioc['iocMachines']:
                # get machine guid
                guid = ioc_machine["AgentID"]

                # Checking if modules of the machines are already cached
                if guid not in machines_modules_ioc.keys():

                    # IOC Score is dependent on IOC Level
                    # providing IOC Score to get modules
                    params = {"iocscore_gte": ioc_level_mapping[str(self._max_ioc_level)]}
                    module_ioc = []

                    # Get all modules of machines
                    ret_value, response = self._paginate_response_data(
                        consts.NWENDPOINT_MACHINES_MODULES_ENDPOINT.format(guid), action_result, "Items", params=params
                    )

                    # something went wrong
                    if phantom.is_fail(ret_value):
                        return action_result.get_status()

                    # get modules' id
                    modules = [module["Id"] for module in response]

                    # get IOC details of each module
                    for machine_module in modules:
                        ret_value, response = self._paginate_response_data(
                            consts.NWENDPOINT_MACHINES_MODULES_INSTANTIOCS_ENDPOINT.format(guid, machine_module),
                            action_result, "Iocs"
                        )

                        if phantom.is_fail(ret_value):
                            return action_result.get_status()

                        module_ioc += response

                        # filtering IOCs whose IOC level is equal to or less than max IOC level
                        module_ioc = [module for module in module_ioc if int(module["IOCLevel"]) <= self._max_ioc_level]

                    # caching modules response to be used if same machine is listed in another IOC
                    machines_modules_ioc[guid] = module_ioc

                # Adding modules information
                ioc['iocModules'] += [machine_module for machine_module in machines_modules_ioc[guid]
                                      if machine_module["IOCName"] == ioc["Name"]]

        ioc_query_list = [ioc for ioc in ioc_query_list if ioc.get('iocMachines')]
        self.save_progress("Total number of IOCs retrieved to ingest: {}".format(len(ioc_query_list)))
        self.ingest_data(ioc_query_list)

        return phantom.APP_SUCCESS

    def _on_poll(self, param):
        """ Function used to ingest endpoint and files related artifacts.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        source_ids = param.get("container_id")
        container_count = int(param.get(phantom.APP_JSON_CONTAINER_COUNT,
                                        consts.NWENDPOINT_DEFAULT_POLL_NOW_CONTAINER_COUNT))

        ioc_queries = []

        # If source_id is not available
        if source_ids is None:
            self.save_progress("Fetching instant IOCs")
            ret_value, response = self._paginate_response_data(consts.NWENDPOINT_INSTANTIOC_ENDPOINT, action_result,
                                                               "iocQueries")

            if phantom.is_fail(ret_value):
                return action_result.get_status()

            ioc_queries = response

        # If source_id is available
        else:
            self.save_progress("Ignoring maximum container count")

            source_id_list = list(filter(None, source_ids.split(",")))

            # Iterate through source_id and fetch the corresponding IOCs
            for source_id in source_id_list:
                # Fetch ioc using source_id
                ret_value, response = self._make_rest_call(
                    consts.NWENDPOINT_GET_IOC_ENDPOINT.format(source_id.strip()),
                    action_result, params=None, method="get")

                # Something went wrong with the request
                if phantom.is_fail(ret_value):
                    return action_result.get_status()

                # Add the available IOC in the list
                if response[consts.NWENDPOINT_REST_RESPONSE].get('iocQuery'):
                    ioc_queries += [response[consts.NWENDPOINT_REST_RESPONSE].get('iocQuery')]

        # Filter IOCs
        instant_iocs = [ioc for ioc in ioc_queries if int(ioc['IOCLevel']) <= self._max_ioc_level and
                        (ioc['MachineCount'] != '0' or ioc['ModuleCount'] != '0')]

        # Get list of IOCs equal to or less then the specified container count
        instant_iocs = instant_iocs[:container_count]

        if instant_iocs:
            response_status = self.get_machine_data(action_result, instant_iocs)
            if phantom.is_fail(response_status):
                return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def finalize(self):
        """ This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.
        """

        self.save_state(self._app_state)
        return phantom.APP_SUCCESS

    def _test_asset_connectivity(self, param):
        """ This function tests the connectivity of an asset with given credentials.

        :param param: (not used in this method)
        :return: status success/failure
        """

        action_result = ActionResult()

        self.save_progress(consts.NWENDPOINT_CONNECTION_TEST_MSG)
        self.save_progress("Configured URL: {}".format(self._url))

        data = {"username": self._username, "password": self._password}

        # making call
        ret_value, response = self._make_rest_call(consts.NWENDPOINT_TEST_CONNECTIVITY_ENDPOINT, action_result,
                                                   data=data, timeout=30)

        # something went wrong
        if phantom.is_fail(ret_value):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, consts.NWENDPOINT_TEST_CONNECTIVITY_FAIL)
            return action_result.get_status()

        self.set_status_save_progress(phantom.APP_SUCCESS, consts.NWENDPOINT_TEST_CONNECTIVITY_PASS)

        return action_result.get_status()

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        # Dictionary mapping each action with its corresponding actions
        supported_actions = {
            'blacklist_domain': self._blacklist_domain,
            'get_scan_data': self._get_scan_data,
            'list_endpoints': self._list_endpoints,
            'blacklist_ip': self._blacklist_ip,
            'scan_endpoint': self._scan_endpoint,
            'get_system_info': self._get_system_info,
            'get_ioc': self._get_ioc,
            'test_asset_connectivity': self._test_asset_connectivity,
            'on_poll': self._on_poll,
            'list_processes': self._list_processes
        }

        action = self.get_action_identifier()

        try:
            run_action = supported_actions[action]
        except:
            raise ValueError('action %r is not supported' % action)

        return run_action(param)


if __name__ == '__main__':

    import sys
    import pudb

    pudb.set_trace()
    if len(sys.argv) < 2:
        print 'No test json specified as input'
        exit(0)
    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print json.dumps(in_json, indent=4)
        connector = NetwitnessendpointConnector()
        connector.print_progress_message = True
        return_value = connector._handle_action(json.dumps(in_json), None)
        print json.dumps(json.loads(return_value), indent=4)
    exit(0)
