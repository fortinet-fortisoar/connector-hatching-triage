""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import json

from requests import request, exceptions as req_exceptions
from connectors.core.connector import get_logger, ConnectorError
from integrations.crudhub import make_request
from os.path import join
from connectors.cyops_utilities.builtins import download_file_from_cyops
from .constants import *


logger = get_logger("hatching-triage")


class HatchingTriage:
    def __init__(self, config, *args, **kwargs):
        server_url = config.get("server_url")
        if not server_url.startswith('https://') and not server_url.startswith('http://'):
            server_url = "https://" + server_url
        self.url = server_url
        self.verify_ssl = config.get("verify_ssl")
        self.api_key = config.get("api_key")

    def api_request(self, method, endpoint, params={}, data={}, files=None):
        try:
            endpoint = self.url + endpoint
            headers = {"Authorization": f"Bearer {self.api_key}"}
            response = request(method, endpoint, headers=headers, params=params, data=data, files=files, verify=self.verify_ssl)

            if response.status_code in [200, 201, 204]:
                if response.text != "":
                    return response.json()
                else:
                    return True
            else:
                if response.text != "":
                    err_resp = response.json()
                    failure_msg = err_resp.get("message") or err_resp.get("error", {}).get("message")
                    error_msg = 'Response [{0}:{1} Details: {2}]'.format(response.status_code, response.reason,
                                                                         failure_msg if failure_msg else '')
                else:
                    error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
                logger.error(error_msg)
                raise ConnectorError(error_msg)
        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            raise ConnectorError(str(err))


def build_params(params):
    new_params = {}
    for key, value in params.items():
        if value is False or value == 0 or value:
            new_params[key] = value
    return new_params


def handle_params(params):
    value = str(params.get('value'))
    input_type = params.get('input')
    try:
        if isinstance(value, bytes):
            value = value.decode('utf-8')
        if input_type == 'Attachment ID':
            if not value.startswith('/api/3/attachments/'):
                value = '/api/3/attachments/{0}'.format(value)
            attachment_data = make_request(value, 'GET')
            file_iri = attachment_data['file']['@id']
            file_name = attachment_data['file']['filename']
            logger.info('file id = {0}, file_name = {1}'.format(file_iri, file_name))
            return file_iri
        elif input_type == 'File IRI':
            if value.startswith('/api/3/files/'):
                return value
            else:
                raise ConnectorError('Invalid File IRI {0}'.format(value))
    except Exception as err:
        logger.info('handle_params(): Exception occurred {0}'.format(err))
        raise ConnectorError('Requested resource could not be found with input type "{0}" and value "{1}"'.format
                             (input_type, value.replace('/api/3/attachments/', '')))


def submitFile(file_iri):
    try:
        file_path = join('/tmp', download_file_from_cyops(file_iri)['cyops_file_path'])
        logger.info(file_path)
        with open(file_path, 'rb') as attachment:
            file_data = attachment.read()
        if file_data:
            files = {'file': file_data}
            return files
        raise ConnectorError('File size too large, submit file up to 32 MB')
    except Exception as Err:
        logger.error('Error in submitFile(): %s' % Err)
        raise ConnectorError('Error in submitFile(): %s' % Err)


def submit_sample(config, params):
    params = build_params(params)
    ob = HatchingTriage(config)
    _type = params.get("kind")
    timeout = params.pop("timeout", None)
    network = params.pop("network", None)
    defaults = dict()
    timeout and defaults.update({"timeout": timeout})
    network and defaults.update({"network": network})
    defaults and params.update({"defaults": defaults})
    if _type == "url":
        if params.get("fetch"):
            params.update({"kind": "fetch"})
        response = ob.api_request(POST, "samples", data=params)
    else:
        file_iri = handle_params(params)
        files = submitFile(file_iri)
        params.update({"file": files})
        response = ob.api_request(POST, "samples", data=params, files=files)
    return response


def query_samples(config, params={}):
    params = build_params(params)
    ob = HatchingTriage(config)
    return ob.api_request(GET, "samples", params=params)


def get_sample(config, params):
    sample_id = params.pop("sample_id")
    ob = HatchingTriage(config)
    return ob.api_request(GET, f"samples/{sample_id}")


def get_sample_summary(config, params):
    sample_id = params.pop("sample_id")
    ob = HatchingTriage(config)
    return ob.api_request(GET, f"samples/{sample_id}/summary")


def set_sample_profile(config, params):
    params = build_params(params)
    sample_id = params.pop("sample_id")
    ob = HatchingTriage(config)
    data = json.dumps(params)
    return ob.api_request(POST, f"samples/{sample_id}/profile", data=data)


def get_static_report(config, params):
    sample_id = params.pop("sample_id")
    ob = HatchingTriage(config)
    return ob.api_request(GET, f"samples/{sample_id}/reports/static")


def get_report_triage(config, params):
    sample_id = params.pop("sample_id")
    task_id = params.pop("task_id")
    ob = HatchingTriage(config)
    return ob.api_request(GET, f"samples/{sample_id}/{task_id}/report_triage.json")


def get_kernel_monitor(config, params):
    sample_id = params.pop("sample_id")
    task_id = params.pop("task_id")
    ob = HatchingTriage(config)
    return ob.api_request(GET, f"samples/{sample_id}/{task_id}/logs/onemon.json")


def create_user(config, params):
    params = build_params(params)
    params.pop("credential_type")
    ob = HatchingTriage(config)
    return ob.api_request(POST, "users", data=json.dumps(params))


def get_profiles(config, params):
    ob = HatchingTriage(config)
    return ob.api_request(GET, "profiles")


def create_profile(config, params):
    params = build_params(params)
    ob = HatchingTriage(config)
    return ob.api_request(POST, "profiles", data=json.dumps(params))


def update_profile(config, params):
    params = build_params(params)
    profile_id = params.pop("profile_id")
    ob = HatchingTriage(config)
    return ob.api_request(PUT, f"profiles/{profile_id}", data=json.dumps(params))


def delete_profile(config, params):
    profile_id = params.pop("profile_id")
    ob = HatchingTriage(config)
    return ob.api_request(DELETE, f"profiles/{profile_id}")


def search_by_query(config, params):
    ob = HatchingTriage(config)
    return ob.api_request(GET, f"search", params=params)


def check_health_ex(config):
    query_samples(config)
    return True


operations = {
    "query_samples": query_samples,
    "submit_sample": submit_sample,
    "get_sample": get_sample,
    "get_sample_summary": get_sample_summary,
    "set_sample_profile": set_sample_profile,
    "get_static_report": get_static_report,
    "get_report_triage": get_report_triage,
    "get_kernel_monitor": get_kernel_monitor,
    "create_user": create_user,
    "get_profiles": get_profiles,
    "create_profile": create_profile,
    "update_profile": update_profile,
    "delete_profile": delete_profile,
    "search_by_query": search_by_query
}
