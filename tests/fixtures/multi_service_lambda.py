"""
Multi-service Lambda function for testing complex analysis
"""

import boto3
import json
import os
from datetime import datetime


def lambda_handler(event, context):
    """Handle events using multiple AWS services"""

    # Initialize clients
    dynamodb = boto3.resource('dynamodb')
    s3_client = boto3.client('s3')
    sns_client = boto3.client('sns')

    # Get configuration from environment
    table_name = os.environ['TABLE_NAME']
    bucket_name = os.environ.get('BUCKET_NAME', 'default-bucket')
    topic_arn = os.environ['TOPIC_ARN']

    table = dynamodb.Table(table_name)

    results = []

    try:
        for record in event['Records']:
            message_id = record['messageId']
            message_body = json.loads(record['body'])

            # Store in DynamoDB
            item = {
                'id': message_id,
                'timestamp': datetime.now().isoformat(),
                'data': message_body,
                'status': 'processing'
            }

            table.put_item(Item=item)

            # Backup to S3
            s3_key = f"backups/{datetime.now().strftime('%Y/%m/%d')}/{message_id}.json"
            s3_client.put_object(
                Bucket=bucket_name,
                Key=s3_key,
                Body=json.dumps(item, default=str),
                ContentType='application/json'
            )

            # Update status
            table.update_item(
                Key={'id': message_id},
                UpdateExpression='SET #status = :status, backup_location = :location',
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={
                    ':status': 'completed',
                    ':location': f's3://{bucket_name}/{s3_key}'
                }
            )

            results.append({
                'message_id': message_id,
                'status': 'completed',
                's3_location': f's3://{bucket_name}/{s3_key}'
            })

        # Send notification
        sns_client.publish(
            TopicArn=topic_arn,
            Subject='Batch Processing Complete',
            Message=json.dumps({
                'processed_count': len(results),
                'results': results
            }, indent=2)
        )

        return {
            'statusCode': 200,
            'body': {
                'message': 'Processing completed successfully',
                'processed_count': len(results)
            }
        }

    except Exception as e:
        # Send error notification
        sns_client.publish(
            TopicArn=topic_arn,
            Subject='Processing Error',
            Message=f'Error occurred: {str(e)}'
        )

        return {
            'statusCode': 500,
            'body': {'error': str(e)}
        }