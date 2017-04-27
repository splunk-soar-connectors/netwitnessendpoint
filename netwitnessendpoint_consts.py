# --
# File: netwitnessendpoint/netwitnessendpoint_consts.py
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

NWENDPOINT_CONFIG_URL = "url"
NWENDPOINT_CONFIG_USERNAME = "username"
NWENDPOINT_CONFIG_PASSWORD = "password"
NWENDPOINT_CONFIG_VERIFY_SSL = "verify_server_cert"
NWENDPOINT_TEST_CONNECTIVITY_ENDPOINT = "/api/v2/auth/credentials?format=json"
NWENDPOINT_BLACKLIST_DOMAIN_ENDPOINT = "/api/v2/blacklist/domain?format=json"
NWENDPOINT_BLOCK_IP_ENDPOINT = "/api/v2/blacklist/ip?format=json"
NWENDPOINT_GET_SCAN_DATA_ENDPOINT = "/api/v2/machines/{}/scandata/{}?format=json"
NWENDPOINT_START_SCAN_ENDPOINT = "/api/v2/machines/{}/scan?format=json"
NWENDPOINT_GET_SYSTEM_INFO_ENDPOINT = "/api/v2/machines/{}?format=json"
NWENDPOINT_GET_IOC_ENDPOINT = "/api/v2/instantiocs/{}?format=json"
NWENDPOINT_GET_IOC_MACHINES_ENDPOINT = "/api/v2/instantiocs/{}/machines?format=json"
NWENDPOINT_INSTANTIOC_ENDPOINT = "/api/v2/instantiocs?format=json"
NWENDPOINT_INSTANTIOC_MACHINE_ENDPOINT = "/api/v2/instantiocs/{}/machines?format=json"
NWENDPOINT_MACHINES_MODULES_ENDPOINT = "/api/v2/machines/{}/modules?format=json"
NWENDPOINT_MACHINES_MODULES_INSTANTIOCS_ENDPOINT = "/api/v2/machines/{}/modules/{}/instantiocs?format=json"
NWENDPOINT_LIST_MACHINES_ENDPOINT = "/api/v2/machines?format=json"
NWENDPOINT_CONNECTION_TEST_MSG = "Querying endpoint to verify the credentials provided"
NWENDPOINT_TEST_CONNECTIVITY_FAIL = "Connectivity test failed"
NWENDPOINT_TEST_CONNECTIVITY_PASS = "Connectivity test succeeded"
NWENDPOINT_ERR_SERVER_CONNECTION = "Connection failed"
NWENDPOINT_ERR_API_UNSUPPORTED_METHOD = "Unsupported method {method}"
NWENDPOINT_EXCEPTION_OCCURRED = "Exception occurred"
NWENDPOINT_ERROR_IOC_QUERY_NOT_EXIST = "IIOC name not found"
NWENDPOINT_REST_RESP_UNAUTHORIZED = 401
NWENDPOINT_REST_RESP_UNAUTHORIZED_MSG = "Invalid username or password"
NWENDPOINT_REST_RESP_SUCCESS = 200
NWENDPOINT_REST_REQUEST_BINDING_EXCEPTION = 400
NWENDPOINT_REST_REQUEST_BINDING_EXCEPTION_MSG = "Unable to bind request"
NWENDPOINT_REST_INVALID_PERMISSION = 403
NWENDPOINT_REST_INVALID_PERMISSION_MSG = "Invalid permission"
NWENDPOINT_REST_RESOURCE_NOT_FOUND = 404
NWENDPOINT_REST_RESOURCE_NOT_FOUND_MSG = "Request not found"
NWENDPOINT_REST_RESPONSE = "response"
NWENDPOINT_REST_RESPONSE_HEADERS = "headers"
NWENDPOINT_REST_RESP_OTHER_ERROR_MSG = "Error returned"
NWENDPOINT_ERR_FROM_SERVER = "API failed\nStatus code: {status}\nDetail: {detail}"
NWENDPOINT_ERR_JSON_PARSE = "Unable to parse the response into a dictionary.\nResponse text - {raw_text}"
NWENDPOINT_JSON_DOMAIN = "domain"
NWENDPOINT_JSON_GUID = "guid"
NWENDPOINT_JSON_LIMIT = "limit"
NWENDPOINT_JSON_NAME = "name"
NWENDPOINT_JSON_IP_ADDRESS = "ip"
NWENDPOINT_JSON_IOC_SCORE_GTE = "iocscore_gte"
NWENDPOINT_JSON_IOC_SCORE_LTE = "iocscore_lte"
NWENDPOINT_JSON_IOC_QUERY = "ioc_query"
NWENDPOINT_JSON_SCAN_CATEGORY = "scan_category"
NWENDPOINT_JSON_CAPTURE_FLOATING_CODE = "capture_floating_code"
NWENDPOINT_JSON_ALL_NETWORK_CONNECTIONS = "all_network_connections"
NWENDPOINT_JSON_FILTER_HOOKS = "filter_hooks"
NWENDPOINT_JSON_RESET_AGENT_NETWORK_CACHE = "reset_agent_network_cache"
NWENDPOINT_JSON_RETRIEVE_MASTER_BOOT_RECORD = "retrieve_master_boot_record"
NWENDPOINT_JSON_CPUMAX = "cpu_max"
NWENDPOINT_JSON_CPUMAXVM = "cpu_max_vm"
NWENDPOINT_JSON_CPUMIN = "cpu_min"
NWENDPOINT_JSON_NOTIFY = "notify"
NWENDPOINT_JSON_INVALID_LIMIT = "Maximum number of records to be fetched must be a positive integer"
NWENDPOINT_JSON_IOC_SCORE_PARAM_ERROR = "Please provide a valid positive integer for filtering IOC Score"
NWENDPOINT_JSON_CPU_MAX_ERROR = "Please provide a valid positive integer for CPU Max"
NWENDPOINT_JSON_CPU_MAX_VM_ERROR = "Please provide a valid positive integer for CPU Max VM"
NWENDPOINT_JSON_CPU_MIN_ERROR = "Please provide a valid positive integer for CPU Min"
NWENDPOINT_START_SCAN_MESSAGE = "Start Scanning successful"
NWENDPOINT_DEFAULT_POLL_NOW_CONTAINER_COUNT = 5
NWENDPOINT_CONTAINER_ERROR = "Error while creating container"
NWENDPOINT_ARTIFACTS_DESC = "Artifact created by NetWitness Endpoint app"
NWENDPOINT_DEFAULT_LIMIT = 50
NWENDPOINT_BLACKLIST_DOMAIN_SUCCESS = "Domain blacklisted successfully"
NWENDPOINT_BLACKLIST_IP_SUCCESS = "IP blacklisted successfully"
