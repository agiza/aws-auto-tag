#!/usr/bin/env python

import boto3
import uuid
import zlib
import json


CLOUDTRAIL_EVENT_NAME = "RunInstances"


def lambda_handler(event, context):
    """ Entry point for lambda function """

    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']

    cloudtrail_log = get_s3_object(bucket, key)
    if not cloudtrail_log:
        return

    print("cloudtrail event: ", cloudtrail_log)

    events = filter_events(cloudtrail_log, CLOUDTRAIL_EVENT_NAME)
    if not events:
        print("No event matching '{}', exiting".format(CLOUDTRAIL_EVENT_NAME))
        return

    count = apply_ec2_tagging(events)
    print("Sucessfully tagged {} resources".format(count))


def get_s3_object(bucket, key):
    """ Verify and get the content of the s3 file """

    s3 = boto3.client('s3')

    waiter = s3.get_waiter('object_exists')
    waiter.wait(Bucket=bucket, Key=key)

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
    file_content = ""
    with open(download_path) as f:
        file_content = f.read()

    return get_human_readable_json(file_content)


def get_human_readable_json(data):
    """ Decompress gzip compressed raw data and return json"""

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

    for record in cloudtrail_records.get("Records", []):
        if record.get("eventName", "") == event_name:
            filtered_events.append(record)

    return filtered_events


def apply_ec2_tagging(cloudtrail_events):
    """ Search in filtered events, ec2 instances to apply tagging """

    total = 0

    for event in cloudtrail_events:
        stack_owner = event.get("userIdentity", {}).get("userName", {})
        stack_owner_arn = event.get("userIdentity", {}).get("arn", {})
        requested_instances = event.get(
            "responseElements", {}).get("instancesSet", {}).get("items")

        if requested_instances:
            total += tag_instances(
                requested_instances, stack_owner, stack_owner_arn
            )

    return total


def tag_instances(requested_instances, stack_owner, stack_owner_arn):
    """ Apply the tag to the EC2 instance """

    tagged_resources_count = 0
    ec2 = boto3.client('ec2')
    instances_ids = []

    for requested_instance in requested_instances:
        instance_id = requested_instance.get("instanceId", "")
        instances_ids.append(instance_id)
        tagged_resources_count += 1
        print("instance_id: ", instance_id)

    ec2.create_tags(
        Resources=instances_ids,
        Tags=[
            {'Key': 'StackOwner', 'Value': stack_owner},
            {'Key': 'StackOwnerARN', 'Value': stack_owner_arn}
        ]
    )

    return tagged_resources_count
