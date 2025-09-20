"""
S3 Lambda function for testing S3 service detection
"""

import boto3
import json
from urllib.parse import unquote_plus


def lambda_handler(event, context):
    """Process S3 events"""

    s3_client = boto3.client('s3')

    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        key = unquote_plus(record['s3']['object']['key'])

        try:
            # Get the object
            response = s3_client.get_object(Bucket=bucket, Key=key)
            content = response['Body'].read()

            # Process the content (simple uppercase conversion)
            processed = content.decode('utf-8').upper()

            # Save processed file
            processed_key = f"processed/{key}"
            s3_client.put_object(
                Bucket=bucket,
                Key=processed_key,
                Body=processed.encode('utf-8'),
                ContentType='text/plain'
            )

            print(f"Processed {key} -> {processed_key}")

        except Exception as e:
            print(f"Error processing {key}: {str(e)}")
            raise e

    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': f'Successfully processed {len(event["Records"])} files'
        })
    }