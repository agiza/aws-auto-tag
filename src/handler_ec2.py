#!/usr/bin/env python

import boto3
import botocore
import uuid
import zlib
import json


CLOUDTRAIL_EVENT_NAME = "RunInstances"


def lambda_handler(event, context):
    """ Entry point for lambda function """

    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']

    cloudtrail_file = get_s3_file(bucket, key)
    if not cloudtrail_file:
        print("Error: Unable to get cloudtrail event log file")
        return

    cloudtrail_log = get_human_readable_json(cloudtrail_file)
    if not cloudtrail_log:
        print("Error: cloudtrail json parsing failed")
        return

    print("cloudtrail event: ", cloudtrail_log)

    events = filter_events(
        cloudtrail_log.get("Records", []), CLOUDTRAIL_EVENT_NAME
    )
    if not events:
        print("No event matching '{}', exiting".format(CLOUDTRAIL_EVENT_NAME))
        return

    payload = filter_ec2_instances(events)
    if not payload:
        print("No instances found in event")
        return

    count = tag_instances(payload)

    print("Sucessfully tagged {} resources".format(count))


def get_s3_file(bucket, key, max_attempts=5):
    """ download the cloudtrail's s3 file and returns its location """

    s3 = boto3.client('s3')

    waiter = s3.get_waiter('object_exists')
    waiter.config.max_attempts = max_attempts

    try:
        waiter.wait(Bucket=bucket, Key=key)
    except botocore.exceptions.WaiterError:
        print("Object '{}/{}' does not exists".format(bucket, key))
        return

    response = s3.head_object(Bucket=bucket, Key=key)
    if not response:
        print("failed to retrieve object: {}/{}".format(bucket, key))
        return

    print("CONTENT TYPE: " + response['ContentType'])
    print("ETag: " + response['ETag'])
    print("Content-Length: ", response['ContentLength'])
    print("Keyname: " + key)

    download_path = '/tmp/{}'.format(uuid.uuid4())
    s3.download_file(bucket, key, download_path)

    return download_path


def get_human_readable_json(s3_file):
    """ Decompress gzip compressed s3 file and return json"""

    data = None
    if not s3_file:
        return None

    try:
        with open(s3_file) as f:
            data = f.read()
    except IOError as e:
        print("Error: unable to open file [{}]".format(e))
        return None

    data = zlib.decompress(data, 16+zlib.MAX_WBITS)
    json_format = None

    try:
        json_format = json.loads(data)
    except ValueError:
        print("Error: failed to get json from data")

    return json_format


def filter_events(cloudtrail_records, event_name):
    """ Look for the right event and find the right resources"""
    filtered_events = []
    cloudtrail_records = cloudtrail_records or []

    for record in cloudtrail_records:
        if record.get("eventName", "") == event_name:
            filtered_events.append(record)

    return filtered_events


def filter_ec2_instances(cloudtrail_events):
    """ Search in filtered events, ec2 instances to apply tags to """

    targeted_instances = []

    for event in cloudtrail_events:
        stack_owner = event.get("userIdentity", {}).get("userName", {})
        stack_owner_arn = event.get("userIdentity", {}).get("arn", {})
        requested_instances = event.get(
            "responseElements", {}).get("instancesSet", {}).get("items")

        if requested_instances:
            target_instance = {
                "owner": stack_owner,
                "owner_arn": stack_owner_arn,
                "instances": [
                    i.get("instanceId", "") for i in requested_instances
                ]
            }
            targeted_instances.append(target_instance)

    return targeted_instances


def tag_instances(payload):
    """
    Apply the tags to the EC2 instances with a payload like:
    [
        {
            "instances": ['instance-id', ...],
            "owner": 'stack_owner'
            "owner_arn": 'stack_owner_arn'
        },
        ...
    ]
    """

    payload = payload or []

    tagged_resources_count = 0
    ec2 = boto3.client('ec2')

    for event in payload:
        ec2.create_tags(
            Resources=event.get("instances", []),
            Tags=[
                {'Key': 'StackOwner', 'Value': event.get("owner")},
                {'Key': 'StackOwnerARN', 'Value': event.get("owner_arn")}
            ]
        )
        tagged_resources_count += len(event.get("instances", []))

    return tagged_resources_count
