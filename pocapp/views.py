from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, HttpResponse
from rest_framework.views import APIView
from rest_framework.response import Response
import subprocess
import requests
import argparse
import os
import time
import datetime
import googleapiclient.discovery
from six.moves import input
import copy
from google.cloud import storage
from google.cloud import bigquery
import google.auth
import binascii
import collections
import hashlib
import sys
from google.oauth2 import service_account
import six
from six.moves.urllib.parse import quote
import smtplib, ssl
from email.message import EmailMessage



credential_path = "/Users/chinmay.parkar/Downloads/cparkar-project-310718-5303640b183d.json"
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = credential_path

class APIConfig(APIView):
    def post(self, request):
        task = request.data
        project=task['project_id']
        location=task['location']
        bucket_name=task['bucket_name']
        db_name=task['db_name']
        create_bucket(project,bucket_name)
        add_bucket_iam_member(bucket_name)
        create_bq_dataset(project, location, db_name)
        add_bq_iam_member(project, db_name)
        create_bq_table(project)
        deploy_cloud_function()
        #create_datalab_instance()
        #zone=task['zone']
        #name=task['name']
        #machine=task['machine']
        #create_datalab_instance(name, machine, project, zone)
        #bucket_metadata(bucket_name)
        #generate_signed_url(bucket_name)
        #generate_upload_signed_url_v4(bucket_name, "file1.csv")
        #set_bucket_public_iam(bucket_name)
        #send_gmail()
        #main(project,zone,name)
        return JsonResponse(bucket_metadata(bucket_name))

def create_bucket(project, bucket_name):
    storage_client = storage.Client(project)
    bucket = storage_client.create_bucket(bucket_name, location='us-east1')
    print("Bucket {} created".format(bucket.name))

def add_bucket_iam_member(bucket_name):
    role = "roles/storage.objectAdmin"
    member = "user:chinmay.parkar@egen.solutions"

    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)

    policy = bucket.get_iam_policy(requested_policy_version=3)

    policy.bindings.append({"role": role, "members": {member}})

    bucket.set_iam_policy(policy)

    print("Added {} with role {} to {}.".format(member, role, bucket_name))

def create_bq_dataset(project, location, db_name):
    credentials, project = google.auth.default(
        scopes = ['https://www.googleapis.com/auth/bigquery']
    )
    bq_client = bigquery.Client(
        project=project,
        credentials=credentials
    )

    Dataset_id = db_name
    dataset_ref = bq_client.dataset(Dataset_id)
    dataset = bigquery.Dataset(dataset_ref)
    dataset.location = location

    try:
        dataset = bq_client.create_dataset(dataset)
    except google.api_core.exceptions.AlreadyExists:
        pass


def add_bq_iam_member(project, db_name): 
    client = bigquery.Client()
    name = project + "." + db_name
    dataset = client.get_dataset(name) 

    entry = bigquery.AccessEntry(
        role="OWNER",
        entity_type="userByEmail",
        entity_id="chinmay.parkar@egen.solutions",
    )

    entries = list(dataset.access_entries)
    entries.append(entry)
    dataset.access_entries = entries

    dataset = client.update_dataset(dataset, ["access_entries"]) 

    full_dataset_id = "{}.{}".format(dataset.project, dataset.dataset_id)
    print(
        "Updated dataset '{}' with modified user permissions.".format(full_dataset_id)
    )


def create_bq_table(project):
    credentials, project = google.auth.default(
        scopes = ['https://www.googleapis.com/auth/bigquery']
    )
    bq_client = bigquery.Client(
        project=project,
        credentials=credentials
    )

    Dataset_id = 'egen_poc_dataset'
    Table_id = 'egen_poc_table'
    dataset_ref = bq_client.dataset(Dataset_id)

    table_schema = [
        bigquery.SchemaField('Sno', 'INTEGER', mode='NULLABLE'),
        bigquery.SchemaField('State', 'STRING', mode='NULLABLE'),
        bigquery.SchemaField('ConfirmedIndianNational', 'INTEGER', mode='NULLABLE'),
        bigquery.SchemaField('ConfirmedForeignNational', 'INTEGER', mode='NULLABLE'),
        bigquery.SchemaField('Cured', 'INTEGER', mode='NULLABLE'),
        bigquery.SchemaField('Deaths', 'INTEGER', mode='NULLABLE'),
        bigquery.SchemaField('Confirmed', 'INTEGER', mode='NULLABLE')
    ] 
    table_ref = dataset_ref.table(Table_id)
    table = bigquery.Table(table_ref, schema=table_schema)
    table = bq_client.create_table(table)

    if table.table_id == Table_id:
        print('Table {} created successfully.'.format(Table_id))
        

def deploy_cloud_function():
    os.chdir(r"/Users/chinmay.parkar/Desktop/POC/egenpoc/pocapp")
    print("Directory changed for Cloud Function Deployment")
    os.system('gcloud functions deploy gcs_to_bq --entry-point csv_in_gcs_to_table --runtime python37 --memory 256MB --trigger-resource egen-poc-bucket --trigger-event google.storage.object.finalize --service-account poc-app@cparkar-project-310718.iam.gserviceaccount.com --project cparkar-project-310718')
    print("Function successfully created")
    send_gmail()

def send_gmail():
    msg = EmailMessage()
    msg.set_content("You can access your instance from: https://console.cloud.google.com/bigquery?project=cparkar-project-310718 ")
    msg["Subject"] = "Your Bigquery instance"
    msg["From"] = "egenpoc@gmail.com"
    msg["To"] = "chinmay.parkar@egen.solutions"

    context=ssl.create_default_context()

    with smtplib.SMTP("smtp.gmail.com", port=587) as smtp:
        smtp.starttls(context=context)
        smtp.login(msg["From"], "EgenPOC@098")
        smtp.send_message(msg)
        print("Email sent successfully!")




























# Additional functions below

def bucket_metadata(bucket_name):
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(bucket_name)

    console_url = 'https://console.cloud.google.com/storage/browser/' + bucket.name
    url={'url':console_url}
    print(url)
    return url

def generate_signed_url(bucket_name,
                        subresource=None, expiration=604800, http_method='GET',
                        query_parameters=None, headers=None):
    
    service_account_file = "/Users/chinmay.parkar/Downloads/cparkar-project-310718-5303640b183d.json"
    object_name = "data"
    if expiration > 604800:
        print('Expiration Time can\'t be longer than 604800 seconds (7 days).')
        sys.exit(1)

    escaped_object_name = quote(six.ensure_binary(object_name), safe=b'/~')
    canonical_uri = '/{}'.format(escaped_object_name)

    datetime_now = datetime.datetime.utcnow()
    request_timestamp = datetime_now.strftime('%Y%m%dT%H%M%SZ')
    datestamp = datetime_now.strftime('%Y%m%d')

    google_credentials = service_account.Credentials.from_service_account_file(
        service_account_file)
    client_email = google_credentials.service_account_email
    credential_scope = '{}/auto/storage/goog4_request'.format(datestamp)
    credential = '{}/{}'.format(client_email, credential_scope)

    if headers is None:
        headers = dict()
    host = '{}.storage.googleapis.com'.format(bucket_name)
    headers['host'] = host

    canonical_headers = ''
    ordered_headers = collections.OrderedDict(sorted(headers.items()))
    for k, v in ordered_headers.items():
        lower_k = str(k).lower()
        strip_v = str(v).lower()
        canonical_headers += '{}:{}\n'.format(lower_k, strip_v)

    signed_headers = ''
    for k, _ in ordered_headers.items():
        lower_k = str(k).lower()
        signed_headers += '{};'.format(lower_k)
    signed_headers = signed_headers[:-1]  # remove trailing ';'

    if query_parameters is None:
        query_parameters = dict()
    query_parameters['X-Goog-Algorithm'] = 'GOOG4-RSA-SHA256'
    query_parameters['X-Goog-Credential'] = credential
    query_parameters['X-Goog-Date'] = request_timestamp
    query_parameters['X-Goog-Expires'] = expiration
    query_parameters['X-Goog-SignedHeaders'] = signed_headers
    if subresource:
        query_parameters[subresource] = ''

    canonical_query_string = ''
    ordered_query_parameters = collections.OrderedDict(
        sorted(query_parameters.items()))
    for k, v in ordered_query_parameters.items():
        encoded_k = quote(str(k), safe='')
        encoded_v = quote(str(v), safe='')
        canonical_query_string += '{}={}&'.format(encoded_k, encoded_v)
    canonical_query_string = canonical_query_string[:-1]  # remove trailing '&'

    canonical_request = '\n'.join([http_method,
                                   canonical_uri,
                                   canonical_query_string,
                                   canonical_headers,
                                   signed_headers,
                                   'UNSIGNED-PAYLOAD'])

    canonical_request_hash = hashlib.sha256(
        canonical_request.encode()).hexdigest()

    string_to_sign = '\n'.join(['GOOG4-RSA-SHA256',
                                request_timestamp,
                                credential_scope,
                                canonical_request_hash])

    # signer.sign() signs using RSA-SHA256 with PKCS1v15 padding
    signature = binascii.hexlify(
        google_credentials.signer.sign(string_to_sign)
    ).decode()

    scheme_and_host = '{}://{}'.format('https', host)
    signed_url = '{}{}?{}&x-goog-signature={}'.format(
        scheme_and_host, canonical_uri, canonical_query_string, signature)
    print (signed_url)
    return signed_url

def generate_upload_signed_url_v4(bucket_name, blob_name):
    """Generates a v4 signed URL for uploading a blob using HTTP PUT.

    Note that this method requires a service account key file. You can not use
    this if you are using Application Default Credentials from Google Compute
    Engine or from the Google Cloud SDK.
    """
    credential_path = "/Users/chinmay.parkar/Downloads/cparkar-project-310718-5303640b183d.json"
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = credential_path

    #bucket_name = 'your-bucket-name'
    #blob_name = 'data'

    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    url = blob.generate_signed_url(
        version="v4",
        # This URL is valid for 15 minutes
        expiration=datetime.timedelta(minutes=15),
        # Allow PUT requests using this URL.
        method="PUT",
        content_type="application/octet-stream",
    )

    print("Generated GET signed URL:")
    print(url)
    print("You can use this URL with any user agent, for example:")
    print(
        "curl -X PUT -H 'Content-Type: application/octet-stream' "
        "--upload-file my-file '{}'".format(url)
    )
    return url

def set_bucket_public_iam(bucket_name):
    """Set a public IAM Policy to bucket"""

    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)

    policy = bucket.get_iam_policy(requested_policy_version=3)
    policy.bindings.append(
        {"role": "roles/storage.objectViewer", "members": {"allUsers"}}
    )

    bucket.set_iam_policy(policy)

    print("Bucket {} is now publicly readable".format(bucket.name))


# [START list_instances]
def list_instances(compute, project, zone):
    result = compute.instances().list(project=project, zone=zone).execute()
    return result['items'] if 'items' in result else None
# [END list_instances]

def create_instance(compute, project, zone, name):
    # Get the latest Debian Jessie image.
    image_response = compute.images().getFromFamily(
        project='debian-cloud', family='debian-9').execute()
    source_disk_image = image_response['selfLink']

    # Configure the machine
    machine_type = "zones/%s/machineTypes/n1-standard-1" % zone

    config = {
        'name': name,
        'machineType': machine_type,

        # Specify the boot disk and the image to use as a source.
        'disks': [
            {
                'boot': True,
                'autoDelete': True,
                'initializeParams': {
                    'sourceImage': source_disk_image,
                }
            }
        ],

        # Specify a network interface with NAT to access the public
        # internet.
        'networkInterfaces': [{
            'network': 'global/networks/default',
            'accessConfigs': [
                {'type': 'ONE_TO_ONE_NAT', 'name': 'External NAT'}
            ]
        }],

    }

    return compute.instances().insert(
        project=project,
        zone=zone,
        body=config).execute()
# [END create_instance

def delete_instance(compute, project, zone, name):
    return compute.instances().delete(
        project=project,
        zone=zone,
        instance=name).execute()

# [START wait_for_operation]
def wait_for_operation(compute, project, zone, operation):
    print('Waiting for operation to finish...')
    while True:
        result = compute.zoneOperations().get(
            project=project,
            zone=zone,
            operation=operation).execute()

        if result['status'] == 'DONE':
            print("done.")
            if 'error' in result:
                raise Exception(result['error'])
            return result

        time.sleep(1)
# [END wait_for_operation]

def main(project, zone, instance_name, wait=True):
    compute = googleapiclient.discovery.build('compute', 'v1')

    print('Creating instance.')

    operation = create_instance(compute, project, zone, instance_name)
    wait_for_operation(compute, project, zone, operation['name'])

    instances = list_instances(compute, project, zone)

    print('Instances in project %s and zone %s:' % (project, zone))
    for instance in instances:
        print(' - ' + instance['name'])
    if wait:
        input()

    print('Deleting instance.')

    operation = delete_instance(compute, project, zone, instance_name)
    wait_for_operation(compute, project, zone, operation['name'])

def create_datalab_instance():
    os.chdir(r"/Users/chinmay.parkar/Desktop/POC/egenpoc/pocapp")
    print("Directory changed for Datalab Deployment")
    os.system('datalab beta create-gpu egen_poc_datalab --machine-type e2-standard-2 --service-account poc-app@cparkar-project-310718.iam.gserviceaccount.com --project cparkar-project-310718')
    print("Datalab successfully created")


    
    






