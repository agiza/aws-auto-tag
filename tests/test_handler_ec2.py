# -*- coding: utf-8 -*-

import json
import boto3

from src.handler_ec2 import tag_instances
from src.handler_ec2 import filter_ec2_instances
from src.handler_ec2 import filter_events
from src.handler_ec2 import get_human_readable_json
from src.handler_ec2 import get_s3_file
from src.handler_ec2 import CLOUDTRAIL_EVENT_NAME

from moto import mock_s3
from moto import mock_ec2


@mock_s3
def test_get_s3_file_with_wrong_bucket():
    assert get_s3_file("dummy-bucket", "dummy-key", max_attempts=1) is None


@mock_s3
def test_get_s3_file():
    s3 = boto3.client('s3')
    bucket = "test-bucket"
    key = "test-key"

    s3.create_bucket(Bucket=bucket)

    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body="dummy content",
        ContentType='text/plain'
    )
    assert get_s3_file(bucket, key) is not None
    assert type(get_s3_file(bucket, key)) is str
    assert len(get_s3_file(bucket, key)) > 0


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


def test_filter_ec2_instances():

    with open("tests/mocks/trail-event-ec2.json") as f:
        events = [json.loads(f.read())]

    instances = filter_ec2_instances(events)
    assert instances is not None
    assert len(instances) == 1
    assert len(instances[0].get("instances")) == 1
    assert len(instances[0].get("owner_arn")) > 0


def test_tag_instances_without_instances():

    assert tag_instances(None) == 0


@mock_ec2
def test_tag_instances():

    base_ami = "ami-1234abcd"
    ec2 = boto3.client('ec2')

    reservation = ec2.run_instances(
        ImageId=base_ami, MinCount=2, MaxCount=2
    )
    instance = reservation["Instances"][0]
    instance2 = reservation["Instances"][1]
    payload = [
        {
            "owner": "test",
            "owner_arn": "arn:aws:iam::364771791306:test",
            "instances": [
                instance.get("InstanceId"),
                instance2.get("InstanceId")
            ]
        }
    ]
    assert tag_instances(payload) == 2
