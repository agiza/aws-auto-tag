# -*- coding: utf-8 -*-

import json

# from src.handler_ec2 import get_human_readable_json
from src.handler_ec2 import tag_instances
from src.handler_ec2 import filter_events
from src.handler_ec2 import get_human_readable_json
from src.handler_ec2 import CLOUDTRAIL_EVENT_NAME


def test_get_human_readble_json():

    assert 1 == 1


def test_tag_instances_without_instances():

    r_instances = None
    stack_onwer = "test"
    stack_owner_arn = "test-arn"

    assert tag_instances(r_instances, stack_onwer, stack_owner_arn) == 0


def test_get_human_readable_json_wrong_file():

    s3_file = None
    assert get_human_readable_json(s3_file) is None

    s3_file = "dummy-file.json"
    assert get_human_readable_json(s3_file) is None


def test_get_human_readable_json():

    s3_file = "tests/mocks/cloudtrail-encoded-event.json.gz"
    assert get_human_readable_json(s3_file) is not None
    assert type(get_human_readable_json(s3_file)) is dict
    assert len(get_human_readable_json(s3_file)) == 1


def test_filter_events_no_match():

    events = None
    assert len(filter_events(events, CLOUDTRAIL_EVENT_NAME)) == 0

    with open("tests/mocks/trail-event-no-ec2.json") as f:
        events = [json.loads(f.read())]

    assert len(filter_events(events, CLOUDTRAIL_EVENT_NAME)) == 0


def test_filter_events():

    with open("tests/mocks/trail-event-ec2.json") as f:
        events = [json.loads(f.read())]

    assert len(filter_events(events, CLOUDTRAIL_EVENT_NAME)) == 1
