"""
Intentionally insecure Lambda function for testing security analysis
"""

import boto3
import os
import subprocess

# Security issues in this code for testing
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # Hardcoded AWS access key
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # Hardcoded secret
API_KEY = "sk-1234567890abcdef"  # Hardcoded API key
DATABASE_URL = "postgresql://user:password@localhost:5432/db"  # Connection string with creds


def lambda_handler(event, context):
    """Insecure Lambda handler for security testing"""

    # Using hardcoded credentials (security issue)
    s3_client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY
    )

    # No error handling (reliability issue)
    bucket = event['bucket']
    key = event['key']

    # Potential command injection (security issue)
    filename = event.get('filename', 'default')
    subprocess.run(f"echo Processing {filename}", shell=True)

    # SQL injection risk (security issue)
    query = f"SELECT * FROM users WHERE name = '{event['user']}'"

    # Logging sensitive data (security issue)
    print(f"Processing with API key: {API_KEY}")
    print(f"Database URL: {DATABASE_URL}")

    # Path traversal risk (security issue)
    file_path = f"/tmp/{event['path']}"
    with open(file_path, 'w') as f:
        f.write("data")

    # No input validation
    response = s3_client.get_object(Bucket=bucket, Key=key)

    return {
        'statusCode': 200,
        'body': response['Body'].read().decode('utf-8')
    }