import os

from google.cloud import bigquery

def csv_in_gcs_to_table(event, context):

    from google.cloud import bigquery

    client = bigquery.Client()

    bucket_name = "egen-poc-bucket"
    object_name = event['name']
    table_id = 'cparkar-project-310718.egen_poc_dataset.egen_poc_table'

    schema = [
            bigquery.SchemaField('Sno', 'INTEGER'),
            bigquery.SchemaField('State', 'STRING'),
            bigquery.SchemaField('ConfirmedIndianNational', 'INTEGER'),
            bigquery.SchemaField('ConfirmedForeignNational', 'INTEGER'),
            bigquery.SchemaField('Cured', 'INTEGER'),
            bigquery.SchemaField('Deaths', 'INTEGER'),
            bigquery.SchemaField('Confirmed', 'INTEGER')]

    job_config = bigquery.LoadJobConfig()
    job_config.schema = schema
    job_config.source_format = bigquery.SourceFormat.CSV
    job_config.write_disposition = bigquery.WriteDisposition().WRITE_APPEND
    job_config.skip_leading_rows = 1

    uri = "gs://{}/{}".format(bucket_name, object_name)

    load_job = client.load_table_from_uri(uri,table_id,job_config=job_config)
    load_job.result()