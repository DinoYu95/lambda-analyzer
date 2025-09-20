"""
Simple Lambda function for testing basic analysis
"""

import json


def lambda_handler(event, context):
    """Simple Lambda handler that just returns success"""

    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Hello from Lambda!',
            'event': event
        })
    }