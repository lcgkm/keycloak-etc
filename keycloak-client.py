#!/usr/bin/env python3

import logging
import os
import sys
import asyncio
import yaml
import json
from csv import DictReader
from collections import defaultdict
from http.client import HTTPConnection
# https://github.com/marcospereirampj/python-keycloak
from keycloak import KeycloakAdmin
from keycloak.exceptions import raise_error_from_response, KeycloakGetError, \
    KeycloakRPTNotFound, KeycloakAuthorizationConfigError, KeycloakInvalidTokenError
from keycloak.urls_patterns import URL_ADMIN_CLIENT, URL_ADMIN_CLIENT_AUTHZ_RESOURCES

# python version check
if (sys.version_info < (3, 0)):
    print(
        '\033[93m' + "DEPRECATION: Python 2.7 reached the end of its life on January 1st, 2020.")
    print('\033[93m' + "Please upgrade your Python as Python 2.7 is no longer maintained." + '\033[0m')

MIN = (3, 7, 3)
if not sys.version_info >= MIN:
    raise EnvironmentError(
        "Python version too low, required at least {}".format('.'.join(str(n) for n in MIN)))


##########################################################################
# Functions

def create_client_authz_resource(keycloak_admin, client_id, payload, skip_exists=False):
    params_path = {"realm-name": keycloak_admin.realm_name,
                   "id": client_id}

    data_raw = keycloak_admin.raw_post(URL_ADMIN_CLIENT_AUTHZ_RESOURCES.format(**params_path),
                                       data=json.dumps(payload))
    return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

def create_client_authz_role_based_policy(keycloak_admin, client_id, payload, skip_exists=False):
    params_path = {"realm-name": keycloak_admin.realm_name,
                   "id": client_id}

    data_raw = keycloak_admin.raw_post(URL_ADMIN_CLIENT_AUTHZ_ROLE_BASED_POLICY.format(**params_path),
                                       data=json.dumps(payload))
    return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

def create_client_authz_role_based_permission(keycloak_admin, client_id, payload, skip_exists=False):
    params_path = {"realm-name": keycloak_admin.realm_name,
                   "id": client_id}

    data_raw = keycloak_admin.raw_post(URL_ADMIN_CLIENT_AUTHZ_ROLE_BASED_PERMISSION.format(**params_path),
                                       data=json.dumps(payload))
    return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

def get_client_authz_policies(keycloak_admin, client_id):
    params_path = {"realm-name": keycloak_admin.realm_name, "id": client_id}
    params_query = {"first": 0, "max": 20, "permission": False}
    data_raw = keycloak_admin.raw_get(URL_ADMIN_CLIENT_AUTHZ_POLICIES.format(**params_path), **params_query)
    return raise_error_from_response(data_raw, KeycloakGetError)
