#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2023, Jakob Pfender <jakob.pfender@safetyio.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
#
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: datadog_synthetics
short_description: Manages Datadog Synthetics tests
description:
  - Manages Synthetics tests within Datadog.
  - Options as described on https://docs.datadoghq.com/api/latest/synthetics.
author: Jakob Pfender (@jpfender)
requirements: [datadog]
extends_documentation_fragment:
  - community.general.attributes
attributes:
    check_mode:
        support: none
    diff_mode:
        support: none
options:
    api_key:
        description:
          - Your Datadog API key.
        required: true
        type: str
    api_host:
        description:
          - The URL to the Datadog API. Default value is https://api.datadoghq.com.
        required: false
        type: str
    app_key:
        description:
          - Your Datadog app key.
        required: true
        type: str
    state:
        description:
          - The designated state of the test.
        required: true
        choices: ['present', 'absent', 'pause', 'unpause']
        type: str
    tags:
        description:
          - A list of tags to associate with your test when creating or updating.
          - This can help you categorize and filter tests.
        type: list
        elements: str
    name:
        description:
          - The name of the alert.
        required: true
        type: str
    notification_message:
        description:
          - A message to include with notifications for this test.
          - Email notifications can be sent to specific users by using the '@username' notation.
          - Test message template variables can be accessed by using double square brackets, i.e '[[' and ']]'.
        type: str
    renotify_interval:
        description:
          - The number of minutes after the last notification before a test will re-notify on the current status.
          - It will only re-notify if it is not resolved.
        type: str
    id:
        description:
          - The ID of the alert.
          - If set, 'ill be used instead of the name to locate the alert.
        type: str
    assertions:
        description:
            - Array of assertions used for the test.
        required: true
        type: list
        elements: str
    target_api_key:
        description:
            - The API key for the host this test should query.
        type: str
        default: ""
    additional_headers:
        description:
         - Additional headers to add to the request.
        type: str
        default: "{}"
    method:
        description:
            - The HTTP method.
        choices: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
        type: str
    body:
        description:
            - The body for the request.
        type: str
        default: ""
    body_type:
        description:
            - The type of the request body.
        choices: ['text/plain', 'application/json', 'text/xml', 'text/html', 'application/x-www-form-urlencoded', 'graphql']
        type: str
        default: "application/json"
    timeout:
        description:
            - Timeout in seconds for the test.
        type: str
    url:
        description:
            - URL to perform the test with.
        type: str
    locations:
        description:
            - Array of locations to run the test with.
        type: list
        elements: str
    min_failure_duration:
        description:
            - Minimum amount of time in failure required to trigger an alert.
        type: str
    min_location_failed:
        description:
            - Minimum number of locations in failure required to trigger an alert.
        type: str
    test_name:
        description:
            - The test name is used for the alert title as well as for all test dashboard widgets and SLOs.
        type: str
        default: ""
    retry_count:
        description:
            - Number of times a test needs to be retried before marking a location as failed.
            - Defaults to 0.
        type: str
    retry_interval:
        description:
            - Time interval between retries (in milliseconds).
            - Defaults to 300ms.
        type: str
    tick_every:
        description:
            - The frequency at which to run the Synthetics test (in seconds).
        choices: ['60', '300', '900', '1800', '3600', '21600', '43200', '86400', '604800']
        type: str
    status:
        description:
            - Define whether you want to start ('live') or pause
              ('paused') a Synthetics test.
            - Defaults to 'paused'.
        choices: ['live', 'paused']
        type: str
        default: "paused"
    type:
        description:
            - Type of the Synthetic test.
            - Defaults to 'api'.
        choices: ['api', browser]
        type: str
        default: "api"
    subtype:
        description:
            - The sub-type of the Synthetic API test.
            - Defaults to 'http'.
        choices: ['http', 'ssl', 'tcp', 'dns']
        type: str
        default: "http"
"""

EXAMPLES = """
# Create a synthetics test
- community.general.datadog_synthetics:
    name: "Example Health Test"
    api_key: "9775a026f1ca7d1c6c5af9d94d9595a4"
    app_key: "87ce4a24b5553d2e482ea8a8500e71b8ad4554ff"
    notification_message: "Health check failed. @your.email@safetyio.com"
    tags:
        - "{{ project }}"
        - "{{ cluster }}"
    state: 'present'
    assertions:
        - '{ "operator": "lessThan", "type": "responseTime", "target": 5001 }'
        - '{ "operator": "is", "type": "statusCode", "target": 200 }'
        - '{ "operator": "is", "property": "content-type", "type": "header", "target": "application/json" }'
        - '{ "operator": "validatesJSONPath", "type": "body", "target": { \
                "operator": "doesNotContain", \
                "targetValue": "error", \
                "jsonPath": "$.ResponseTime" \
            } }'
    target_api_key: "abc1"
    method: 'GET'
    timeout: '30'
    url: "https://example.com/prod/v1/echo"
    locations:
        - 'aws:us-east-2'
        - 'aws:us-west-2'
        - 'aws:eu-central-1'
    min_failure_duration: '0'
    min_location_failed: '1'
    test_name: !unsafe 'Example test status is {{#is_alert}}DOWN{{/is_alert}}{{#is_recovery}}UP{{/is_recovery}}'
    retry_count: '1'
    retry_interval: '300'
    tick_every: '3600'
    renotify_interval: '10'

# Delete a test
- community.general.datadog_synthetics:
    name: "Example Health Test"
    state: "absent"
    api_key: "9775a026f1ca7d1c6c5af9d94d9595a4"
    app_key: "87ce4a24b5553d2e482ea8a8500e71b8ad4554ff"

# Pause a test
- community.general.datadog_synthetics:
    name: "Example Health Test"
    state: "pause"
    api_key: "9775a026f1ca7d1c6c5af9d94d9595a4"
    app_key: "87ce4a24b5553d2e482ea8a8500e71b8ad4554ff"

# Unpause a test
- community.general.datadog_synthetics:
    name: "Example Health Test"
    state: "unpause"
    api_key: "9775a026f1ca7d1c6c5af9d94d9595a4"
    app_key: "87ce4a24b5553d2e482ea8a8500e71b8ad4554ff"
"""
import json
import traceback

# Import Datadog
DATADOG_IMP_ERR = None
try:
    from datadog import initialize
    from datadog.api.exceptions import DatadogException
    from datadog.api.synthetics import Synthetics

    HAS_DATADOG = True
except ModuleNotFoundError:
    DATADOG_IMP_ERR = traceback.format_exc()
    HAS_DATADOG = False

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule, missing_required_lib


def main():
    """
    Module entry point. Arguments are passed through from the calling
    play.
    """
    module = AnsibleModule(
        argument_spec=dict(
            api_key=dict(required=True, no_log=True),
            api_host=dict(required=False),
            app_key=dict(required=True, no_log=True),
            state=dict(required=True, choices=["present", "absent", "pause", "unpause"]),
            name=dict(required=True),
            notification_message=dict(required=False, default=None),
            renotify_interval=dict(required=False, default=None),
            tags=dict(required=False, type="list", default=None, elements="str"),
            id=dict(required=False),
            assertions=dict(required=True, type="list", elements="str"),
            target_api_key=dict(required=False, default="", no_log=True),
            additional_headers=dict(required=False, default="{}"),
            method=dict(
                required=False,
                choices=["GET", "POST", "PATCH", "PUT", "DELETE", "HEAD", "OPTIONS"],
            ),
            body=dict(required=False, default=""),
            body_type=dict(
                required=False,
                choices=[
                    "text/plain",
                    "application/json",
                    "text/xml",
                    "text/html",
                    "application/x-www-form-urlencoded",
                    "graphql",
                ],
                default="application/json",
            ),
            timeout=dict(required=False, default=None),
            url=dict(required=False, default=None),
            locations=dict(required=False, type="list", default=None, elements="str"),
            min_failure_duration=dict(required=False, default=None),
            min_location_failed=dict(required=False, default=None),
            test_name=dict(required=False, default=''),
            retry_count=dict(required=False, default=None),
            retry_interval=dict(required=False, default=None),
            tick_every=dict(
                required=False,
                choices=[
                    "60",
                    "300",
                    "900",
                    "1800",
                    "3600",
                    "21600",
                    "43200",
                    "86400",
                    "604800",
                ],
                default=None,
            ),
            status=dict(required=False, choices=["live", "paused"], default="paused"),
            type=dict(required=False, choices=["api", "browser"], default="api"),
            subtype=dict(
                required=False, choices=["http", "ssl", "tcp", "dns"], default="http"
            ),
        )
    )

    # Prepare Datadog
    if not HAS_DATADOG:
        module.fail_json(
            msg=missing_required_lib("datadogpy"), exception=DATADOG_IMP_ERR
        )

    options = {
        "api_key": module.params["api_key"],
        "api_host": module.params["api_host"],
        "app_key": module.params["app_key"],
    }

    initialize(**options)

    # Check if api_key and app_key is correct or not
    # if not, then fail here.
    response = Synthetics.get_all_tests()
    if isinstance(response, dict):
        msg = response.get("errors", None)
        if msg:
            module.fail_json(
                msg="Failed to connect Datadog server using given app_key and api_key : {0}".format(
                    msg[0]
                )
            )

    if module.params["state"] == "present":
        install_test(module)
    elif module.params["state"] == "absent":
        delete_test(module)
    elif module.params["state"] == "unpause":
        unpause_test(module)


def _fix_template_vars(message):
    """
    Sanitize templating in strings by replacing brackets with braces.

    :param message: The message to sanitize.
    :returns: The sanitized message.
    """
    if message:
        return message.replace("[[", "{{").replace("]]", "}}")
    return message


def _get_test(module):
    """
    Retrieve a synthetics test from Datadog.

    Uses either the test's ID or its name to retrieve the test.

    :param module: The Ansible module object.
    :returns: The test if it was found, an empty dict otherwise.
    """
    if module.params["id"] is not None:
        test = Synthetics.get_test(module.params["id"])
        if "errors" in test:
            module.fail_json(
                msg="Failed to retrieve test with id %s, errors are %s"
                % (module.params["id"], str(test["errors"]))
            )
        return test

    tests = Synthetics.get_all_tests()
    for test in tests["tests"]:
        if test["name"] == _fix_template_vars(module.params["name"]):
            return test

    return {}


def _post_test(module, config, options):
    """
    Create a new synthetics test in Datadog.

    :param module: The Ansible module object.
    :param config: The test config containing the request and assertions.
    :param options: The test options (failure thresholds, retries etc.)
    """
    try:
        kwargs = dict(
            config=config,
            message=_fix_template_vars(module.params["notification_message"]),
            name=_fix_template_vars(module.params["name"]),
            options=options,
            status=module.params["status"],
            type=module.params["type"],
            subtype=module.params["subtype"],
        )

        if module.params["locations"] is not None:
            kwargs["locations"] = module.params["locations"]
        if module.params["tags"] is not None:
            kwargs["tags"] = module.params["tags"]

        msg = Synthetics.create_test(**kwargs)

        if "errors" in msg:
            module.fail_json(msg=str(msg["errors"]))
        else:
            module.exit_json(changed=True, msg=msg)
    except DatadogException as err:
        module.fail_json(msg=to_native(err), exception=traceback.format_exc())


def _equal_dicts(first, second, ignore_keys):
    """
    Compare two dicts for equality by comparing keys.

    :param first: The first dict.
    :param second: The second dict.
    :param ignore_keys: Keys to ignore.
    :returns: True if all non-ignored keys match, False otherwise.
    """
    keys_first = set(first).difference(ignore_keys)
    keys_second = set(second).difference(ignore_keys)
    return keys_first == keys_second and all(first[k] == second[k] for k in keys_first)


def _update_test(module, test, config, options):
    """
    Update an existing synthetics test in Datadog.

    :param module: The Ansible module object.
    :param test: The test to update. Must include the test's public_id.
    :param config: The test config containing the request and assertions.
    :param options: The test options (failure thresholds, retries etc.)
    """
    try:
        public_id = test["public_id"]
        kwargs = dict(
            config=config,
            message=_fix_template_vars(module.params["notification_message"]),
            name=_fix_template_vars(module.params["name"]),
            options=options,
            status=module.params["status"],
            type=module.params["type"],
            subtype=module.params["subtype"],
        )
        if module.params["locations"] is not None:
            kwargs["locations"] = module.params["locations"]
        if module.params["tags"] is not None:
            kwargs["tags"] = module.params["tags"]

        msg = Synthetics.edit_test(public_id, **kwargs)

        if "errors" in msg:
            module.fail_json(msg=str(msg["errors"]))
        elif _equal_dicts(msg, test, ["modified_at"]):
            module.exit_json(changed=False, msg=msg)
        else:
            module.exit_json(changed=True, msg=msg)
    except DatadogException as err:
        module.fail_json(msg=to_native(err), exception=traceback.format_exc())


def _set_test_status(module, test, status):
    """
    Set a synthetics test status in Datadog.

    :param module: The Ansible module object.
    :param test: The test to update. Must include the test's public_id.
    :param status: The status to assign to the test ['paused', 'live'].
    """
    try:
        public_id = test["public_id"]
        kwargs = dict(
            config=test["config"],
            message=test["message"],
            name=test["name"],
            options=test["options"],
            status=status,
            locations=test["locations"],
            tags=test["tags"],
            type=test["type"],
            subtype=test["subtype"],
        )

        msg = Synthetics.edit_test(public_id, **kwargs)

        if "errors" in msg:
            module.fail_json(msg=str(msg["errors"]))
        elif _equal_dicts(msg, test, ["modified_at"]):
            module.exit_json(changed=False, msg=msg)
        else:
            module.exit_json(changed=True, msg=msg)

    except DatadogException as err:
        module.fail_json(msg=to_native(err), exception=traceback.format_exc())


def install_test(module):
    """
    Create or update a synthetics test in Datadog.

    If a test of the same name (or the same ID if ID is given)
    already exists, this test is updated, otherwise a new one is
    created.

    :param module: The Ansible module object.
    """
    try:
        assertions = []
        for assertion in module.params["assertions"]:
            assertions.append(json.loads(assertion))

        # We need to perform some sanitization here because Ansible mangles the incoming JSON
        # strings into Python lingo
        additional_headers = module.params["additional_headers"].replace("'", '"')
        body = module.params["body"].replace("'", '"').replace("None", "null")

        config = {
            "assertions": assertions,
            "request": {
                "headers": {
                    "x-api-key": module.params["target_api_key"],
                    "content-type": "application/json",
                }
                | json.loads(additional_headers),
                "method": module.params["method"],
                "body": body,
                "bodyType": module.params["body_type"],
                "timeout": int(module.params["timeout"]),
                "url": module.params["url"],
            },
        }
        options = {
            "min_failure_duration": int(module.params["min_failure_duration"]),
            "min_location_failed": int(module.params["min_location_failed"]),
            "test_name": str(module.params["test_name"]),
            "test_options": {
                "renotify_interval": int(module.params["renotify_interval"]),
            },
            "retry": {
                "count": int(module.params["retry_count"]),
                "interval": int(module.params["retry_interval"]),
            },
            "tick_every": int(module.params["tick_every"]),
        }

        test = _get_test(module)
        if not test:
            _post_test(module, config, options)
        else:
            _update_test(module, test, config, options)

    except DatadogException as err:
        module.fail_json(msg=to_native(err), exception=traceback.format_exc())


def pause_test(module):
    """
    Pause a synthetics test in Datadog.

    :param module: The Ansible module object.
    """
    test = _get_test(module)
    if not test:
        module.exit_json(changed=False)
    try:
        _set_test_status(module, test, 'paused')
    except DatadogException as err:
        module.fail_json(msg=to_native(err), exception=traceback.format_exc())


def unpause_test(module):
    """
    Unpause a synthetics test in Datadog.

    :param module: The Ansible module object.
    """
    test = _get_test(module)
    if not test:
        module.exit_json(changed=False)
    try:
        _set_test_status(module, test, 'live')
    except DatadogException as err:
        module.fail_json(msg=to_native(err), exception=traceback.format_exc())


def delete_test(module):
    """
    Delete a synthetics test in Datadog.

    :param module: The Ansible module object.
    """
    test = _get_test(module)
    if not test:
        module.exit_json(changed=False)
    try:
        msg = Synthetics.delete_test(public_ids=[test["public_id"]])
        module.exit_json(changed=True, msg=msg)
    except DatadogException as err:
        module.fail_json(msg=to_native(err), exception=traceback.format_exc())


if __name__ == "__main__":
    main()
