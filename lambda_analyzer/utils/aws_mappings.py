"""
AWS service to IAM permission mappings and helper functions
"""

from typing import Dict, List, Set, Optional
import re

# Complete AWS service mappings
AWS_SERVICE_MAPPINGS = {
    'boto3.client': {
        's3': {
            'service_name': 'Amazon S3',
            'methods': {
                'get_object': ['s3:GetObject'],
                'put_object': ['s3:PutObject'],
                'delete_object': ['s3:DeleteObject'],
                'list_objects_v2': ['s3:ListBucket'],
                'list_objects': ['s3:ListBucket'],
                'head_object': ['s3:GetObject'],
                'copy_object': ['s3:GetObject', 's3:PutObject'],
                'create_bucket': ['s3:CreateBucket'],
                'delete_bucket': ['s3:DeleteBucket'],
                'get_bucket_location': ['s3:GetBucketLocation'],
                'get_bucket_versioning': ['s3:GetBucketVersioning'],
                'put_bucket_versioning': ['s3:PutBucketVersioning'],
                'get_bucket_policy': ['s3:GetBucketPolicy'],
                'put_bucket_policy': ['s3:PutBucketPolicy'],
            }
        },
        'dynamodb': {
            'service_name': 'Amazon DynamoDB',
            'methods': {
                'get_item': ['dynamodb:GetItem'],
                'put_item': ['dynamodb:PutItem'],
                'update_item': ['dynamodb:UpdateItem'],
                'delete_item': ['dynamodb:DeleteItem'],
                'scan': ['dynamodb:Scan'],
                'query': ['dynamodb:Query'],
                'batch_get_item': ['dynamodb:BatchGetItem'],
                'batch_write_item': ['dynamodb:BatchWriteItem'],
                'create_table': ['dynamodb:CreateTable'],
                'delete_table': ['dynamodb:DeleteTable'],
                'describe_table': ['dynamodb:DescribeTable'],
                'list_tables': ['dynamodb:ListTables'],
                'update_table': ['dynamodb:UpdateTable'],
            }
        },
        'sns': {
            'service_name': 'Amazon SNS',
            'methods': {
                'publish': ['sns:Publish'],
                'create_topic': ['sns:CreateTopic'],
                'delete_topic': ['sns:DeleteTopic'],
                'get_topic_attributes': ['sns:GetTopicAttributes'],
                'set_topic_attributes': ['sns:SetTopicAttributes'],
                'subscribe': ['sns:Subscribe'],
                'unsubscribe': ['sns:Unsubscribe'],
                'list_topics': ['sns:ListTopics'],
                'list_subscriptions': ['sns:ListSubscriptions'],
            }
        },
        'sqs': {
            'service_name': 'Amazon SQS',
            'methods': {
                'send_message': ['sqs:SendMessage'],
                'receive_message': ['sqs:ReceiveMessage'],
                'delete_message': ['sqs:DeleteMessage'],
                'send_message_batch': ['sqs:SendMessage'],
                'delete_message_batch': ['sqs:DeleteMessage'],
                'create_queue': ['sqs:CreateQueue'],
                'delete_queue': ['sqs:DeleteQueue'],
                'get_queue_attributes': ['sqs:GetQueueAttributes'],
                'set_queue_attributes': ['sqs:SetQueueAttributes'],
                'list_queues': ['sqs:ListQueues'],
                'purge_queue': ['sqs:PurgeQueue'],
            }
        },
        'lambda': {
            'service_name': 'AWS Lambda',
            'methods': {
                'invoke': ['lambda:InvokeFunction'],
                'invoke_async': ['lambda:InvokeFunction'],
                'create_function': ['lambda:CreateFunction'],
                'delete_function': ['lambda:DeleteFunction'],
                'update_function_code': ['lambda:UpdateFunctionCode'],
                'update_function_configuration': ['lambda:UpdateFunctionConfiguration'],
                'get_function': ['lambda:GetFunction'],
                'list_functions': ['lambda:ListFunctions'],
            }
        },
        'secretsmanager': {
            'service_name': 'AWS Secrets Manager',
            'methods': {
                'get_secret_value': ['secretsmanager:GetSecretValue'],
                'create_secret': ['secretsmanager:CreateSecret'],
                'delete_secret': ['secretsmanager:DeleteSecret'],
                'update_secret': ['secretsmanager:UpdateSecret'],
                'describe_secret': ['secretsmanager:DescribeSecret'],
                'list_secrets': ['secretsmanager:ListSecrets'],
                'put_secret_value': ['secretsmanager:PutSecretValue'],
            }
        },
        'ssm': {
            'service_name': 'AWS Systems Manager',
            'methods': {
                'get_parameter': ['ssm:GetParameter'],
                'get_parameters': ['ssm:GetParameters'],
                'get_parameters_by_path': ['ssm:GetParametersByPath'],
                'put_parameter': ['ssm:PutParameter'],
                'delete_parameter': ['ssm:DeleteParameter'],
                'describe_parameters': ['ssm:DescribeParameters'],
            }
        },
        'logs': {
            'service_name': 'Amazon CloudWatch Logs',
            'methods': {
                'create_log_group': ['logs:CreateLogGroup'],
                'create_log_stream': ['logs:CreateLogStream'],
                'put_log_events': ['logs:PutLogEvents'],
                'describe_log_groups': ['logs:DescribeLogGroups'],
                'describe_log_streams': ['logs:DescribeLogStreams'],
                'get_log_events': ['logs:GetLogEvents'],
                'filter_log_events': ['logs:FilterLogEvents'],
            }
        },
        'kinesis': {
            'service_name': 'Amazon Kinesis',
            'methods': {
                'put_record': ['kinesis:PutRecord'],
                'put_records': ['kinesis:PutRecords'],
                'get_records': ['kinesis:GetRecords'],
                'get_shard_iterator': ['kinesis:GetShardIterator'],
                'describe_stream': ['kinesis:DescribeStream'],
                'list_streams': ['kinesis:ListStreams'],
            }
        },
        'cloudwatch': {
            'service_name': 'Amazon CloudWatch',
            'methods': {
                'put_metric_data': ['cloudwatch:PutMetricData'],
                'get_metric_statistics': ['cloudwatch:GetMetricStatistics'],
                'list_metrics': ['cloudwatch:ListMetrics'],
                'get_metric_data': ['cloudwatch:GetMetricData'],
            }
        }
    },
    'boto3.resource': {
        'dynamodb': {
            'service_name': 'Amazon DynamoDB',
            'table_methods': {
                'get_item': ['dynamodb:GetItem'],
                'put_item': ['dynamodb:PutItem'],
                'update_item': ['dynamodb:UpdateItem'],
                'delete_item': ['dynamodb:DeleteItem'],
                'scan': ['dynamodb:Scan'],
                'query': ['dynamodb:Query'],
            }
        },
        's3': {
            'service_name': 'Amazon S3',
            'bucket_methods': {
                'upload_file': ['s3:PutObject'],
                'download_file': ['s3:GetObject'],
                'upload_fileobj': ['s3:PutObject'],
                'download_fileobj': ['s3:GetObject'],
                'objects': ['s3:ListBucket'],
            }
        }
    }
}


def get_service_display_name(service: str) -> str:
    """Get human-readable display name for AWS service"""
    client_mapping = AWS_SERVICE_MAPPINGS.get('boto3.client', {})
    resource_mapping = AWS_SERVICE_MAPPINGS.get('boto3.resource', {})

    if service in client_mapping:
        return client_mapping[service].get('service_name', service.upper())
    elif service in resource_mapping:
        return resource_mapping[service].get('service_name', service.upper())
    else:
        return service.replace('_', ' ').title()


def get_iam_permissions_for_method(service: str, method: str) -> List[str]:
    """Get IAM permissions required for a specific AWS service method"""

    # Check client mappings
    client_mapping = AWS_SERVICE_MAPPINGS.get('boto3.client', {}).get(service, {})
    if 'methods' in client_mapping and method in client_mapping['methods']:
        return client_mapping['methods'][method]

    # Check resource mappings
    resource_mapping = AWS_SERVICE_MAPPINGS.get('boto3.resource', {}).get(service, {})
    for method_group in ['table_methods', 'bucket_methods']:
        if method_group in resource_mapping and method in resource_mapping[method_group]:
            return resource_mapping[method_group][method]

    # Return generic permission if not found
    return [f"{service}:{_method_to_action(method)}"]


def _method_to_action(method: str) -> str:
    """Convert Python method name to AWS IAM action name"""
    # Convert snake_case to PascalCase
    words = method.split('_')
    return ''.join(word.capitalize() for word in words)


def get_resource_arn_pattern(service: str) -> str:
    """Get appropriate resource ARN pattern for service"""
    arn_patterns = {
        's3': "arn:aws:s3:::*/*",
        'dynamodb': "arn:aws:dynamodb:*:*:table/*",
        'sns': "arn:aws:sns:*:*:*",
        'sqs': "arn:aws:sqs:*:*:*",
        'lambda': "arn:aws:lambda:*:*:function:*",
        'secretsmanager': "arn:aws:secretsmanager:*:*:secret:*",
        'ssm': "arn:aws:ssm:*:*:parameter/*",
        'logs': "arn:aws:logs:*:*:*",
        'kinesis': "arn:aws:kinesis:*:*:stream/*",
        'cloudwatch': "*",  # CloudWatch doesn't use ARNs for most actions
    }

    return arn_patterns.get(service, "*")


def optimize_iam_policy(policy: Dict) -> Dict:
    """Optimize IAM policy by consolidating permissions and removing redundancy"""
    if not policy or 'Statement' not in policy:
        return policy

    # Group statements by resource and effect
    resource_groups = {}
    for statement in policy['Statement']:
        resource = statement.get('Resource', '*')
        effect = statement.get('Effect', 'Allow')

        key = (resource, effect)
        if key not in resource_groups:
            resource_groups[key] = {
                'Effect': effect,
                'Action': set(),
                'Resource': resource
            }

        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        resource_groups[key]['Action'].update(actions)

    # Rebuild optimized statements
    optimized_statements = []
    for (resource, effect), group in resource_groups.items():
        optimized_statements.append({
            'Effect': group['Effect'],
            'Action': sorted(list(group['Action'])),
            'Resource': resource
        })

    return {
        'Version': policy.get('Version', '2012-10-17'),
        'Statement': optimized_statements
    }