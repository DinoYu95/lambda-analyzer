"""
IAM Policy Generation Module

This module generates minimal IAM policies based on detected AWS API calls.
"""

import json
from typing import Dict, List, Set, Any


class IAMPolicyGenerator:
    """Generates IAM policies from detected AWS API calls"""

    # AWS API methods to IAM permissions mapping
    API_TO_PERMISSIONS = {
        's3': {
            'get_object': ['s3:GetObject'],
            'put_object': ['s3:PutObject'],
            'delete_object': ['s3:DeleteObject'],
            'list_objects': ['s3:ListBucket'],
            'list_objects_v2': ['s3:ListBucket'],
            'head_object': ['s3:GetObject'],
            'copy_object': ['s3:GetObject', 's3:PutObject'],
            'create_bucket': ['s3:CreateBucket'],
            'delete_bucket': ['s3:DeleteBucket'],
            'get_bucket_location': ['s3:GetBucketLocation'],
            'upload_file': ['s3:PutObject'],
            'download_file': ['s3:GetObject'],
            'upload_fileobj': ['s3:PutObject'],
            'download_fileobj': ['s3:GetObject'],
        },
        'dynamodb': {
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
        },
        'sns': {
            'publish': ['sns:Publish'],
            'create_topic': ['sns:CreateTopic'],
            'delete_topic': ['sns:DeleteTopic'],
            'get_topic_attributes': ['sns:GetTopicAttributes'],
            'set_topic_attributes': ['sns:SetTopicAttributes'],
            'subscribe': ['sns:Subscribe'],
            'unsubscribe': ['sns:Unsubscribe'],
            'list_topics': ['sns:ListTopics'],
            'list_subscriptions': ['sns:ListSubscriptions'],
        },
        'sqs': {
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
        },
        'lambda': {
            'invoke': ['lambda:InvokeFunction'],
            'invoke_async': ['lambda:InvokeFunction'],
            'create_function': ['lambda:CreateFunction'],
            'delete_function': ['lambda:DeleteFunction'],
            'update_function_code': ['lambda:UpdateFunctionCode'],
            'update_function_configuration': ['lambda:UpdateFunctionConfiguration'],
            'get_function': ['lambda:GetFunction'],
            'list_functions': ['lambda:ListFunctions'],
        },
        'secretsmanager': {
            'get_secret_value': ['secretsmanager:GetSecretValue'],
            'create_secret': ['secretsmanager:CreateSecret'],
            'delete_secret': ['secretsmanager:DeleteSecret'],
            'update_secret': ['secretsmanager:UpdateSecret'],
            'describe_secret': ['secretsmanager:DescribeSecret'],
            'list_secrets': ['secretsmanager:ListSecrets'],
            'put_secret_value': ['secretsmanager:PutSecretValue'],
        },
        'ssm': {
            'get_parameter': ['ssm:GetParameter'],
            'get_parameters': ['ssm:GetParameters'],
            'get_parameters_by_path': ['ssm:GetParametersByPath'],
            'put_parameter': ['ssm:PutParameter'],
            'delete_parameter': ['ssm:DeleteParameter'],
            'describe_parameters': ['ssm:DescribeParameters'],
        },
        'logs': {
            'create_log_group': ['logs:CreateLogGroup'],
            'create_log_stream': ['logs:CreateLogStream'],
            'put_log_events': ['logs:PutLogEvents'],
            'describe_log_groups': ['logs:DescribeLogGroups'],
            'describe_log_streams': ['logs:DescribeLogStreams'],
            'get_log_events': ['logs:GetLogEvents'],
            'filter_log_events': ['logs:FilterLogEvents'],
        },
        'kinesis': {
            'put_record': ['kinesis:PutRecord'],
            'put_records': ['kinesis:PutRecords'],
            'get_records': ['kinesis:GetRecords'],
            'get_shard_iterator': ['kinesis:GetShardIterator'],
            'describe_stream': ['kinesis:DescribeStream'],
            'list_streams': ['kinesis:ListStreams'],
        },
        'cloudwatch': {
            'put_metric_data': ['cloudwatch:PutMetricData'],
            'get_metric_statistics': ['cloudwatch:GetMetricStatistics'],
            'list_metrics': ['cloudwatch:ListMetrics'],
            'get_metric_data': ['cloudwatch:GetMetricData'],
        }
    }

    def __init__(self, config: Dict):
        """Initialize with configuration"""
        self.config = config
        self.iam_config = config.get('iam', {})

    def generate_policy(self, api_calls: Dict[str, List[str]]) -> Dict[str, Any]:
        """
        Generate IAM policy from detected API calls

        Args:
            api_calls: Dictionary mapping service names to list of method names

        Returns:
            IAM policy dictionary
        """
        if not api_calls:
            return {}

        statements = []

        for service, methods in api_calls.items():
            service_permissions = self._get_permissions_for_service(service, methods)

            if service_permissions:
                statement = self._create_policy_statement(
                    service, service_permissions
                )
                statements.append(statement)

        if not statements:
            return {}

        policy = {
            "Version": "2012-10-17",
            "Statement": statements
        }

        # Optimize policy if requested
        if self.iam_config.get('optimize', True):
            policy = self._optimize_policy(policy)

        return policy

    def _get_permissions_for_service(self, service: str, methods: List[str]) -> Set[str]:
        """Get IAM permissions needed for service methods"""
        permissions = set()

        service_mappings = self.API_TO_PERMISSIONS.get(service, {})

        for method in methods:
            method_permissions = service_mappings.get(method)
            if method_permissions:
                permissions.update(method_permissions)
            else:
                # Generate generic permission if mapping not found
                generic_permission = f"{service}:{self._method_to_action(method)}"
                permissions.add(generic_permission)

        return permissions

    def _method_to_action(self, method: str) -> str:
        """Convert method name to IAM action name"""
        # Convert snake_case to PascalCase
        words = method.split('_')
        return ''.join(word.capitalize() for word in words)

    def _create_policy_statement(self, service: str, permissions: Set[str]) -> Dict[str, Any]:
        """Create a policy statement for a service"""
        statement = {
            "Effect": "Allow",
            "Action": sorted(list(permissions))
        }

        # Add resource constraints if enabled
        if self.iam_config.get('resource_constraints', True):
            resource_arn = self._get_resource_arn_pattern(service)
            statement["Resource"] = resource_arn
        else:
            statement["Resource"] = "*"

        return statement

    def _get_resource_arn_pattern(self, service: str) -> str:
        """
        Get appropriate resource ARN pattern for service
        In a real implementation, this would be more sophisticated
        """
        arn_patterns = {
            's3': "arn:aws:s3:::*",
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

    def _optimize_policy(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize IAM policy by consolidating statements"""
        if 'Statement' not in policy:
            return policy

        # Group statements by resource
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
            'Version': policy['Version'],
            'Statement': optimized_statements
        }

    def validate_policy(self, policy: Dict[str, Any]) -> List[str]:
        """
        Validate IAM policy structure and return issues

        Args:
            policy: IAM policy dictionary

        Returns:
            List of validation issues/warnings
        """
        issues = []

        if not policy:
            return ["Policy is empty"]

        # Check required fields
        if 'Version' not in policy:
            issues.append("Policy missing 'Version' field")
        elif policy['Version'] not in ['2008-10-17', '2012-10-17']:
            issues.append(f"Invalid policy version: {policy['Version']}")

        if 'Statement' not in policy:
            issues.append("Policy missing 'Statement' field")
            return issues

        statements = policy['Statement']
        if not isinstance(statements, list):
            statements = [statements]

        # Validate each statement
        for i, statement in enumerate(statements):
            self._validate_statement(statement, i, issues)

        return issues

    def _validate_statement(self, statement: Dict, index: int, issues: List[str]) -> None:
        """Validate individual policy statement"""
        # Check Effect
        if 'Effect' not in statement:
            issues.append(f"Statement {index}: Missing 'Effect' field")
        elif statement['Effect'] not in ['Allow', 'Deny']:
            issues.append(f"Statement {index}: Invalid Effect '{statement['Effect']}'")

        # Check Action
        if 'Action' not in statement:
            issues.append(f"Statement {index}: Missing 'Action' field")
        else:
            actions = statement['Action']
            if isinstance(actions, str):
                actions = [actions]

            for action in actions:
                if not isinstance(action, str):
                    issues.append(f"Statement {index}: Action must be string")
                elif ':' not in action and action != '*':
                    issues.append(f"Statement {index}: Malformed action '{action}'")

        # Check Resource (if present)
        if 'Resource' in statement:
            resource = statement['Resource']
            if isinstance(resource, str):
                resource = [resource]

            for res in resource:
                if not isinstance(res, str):
                    issues.append(f"Statement {index}: Resource must be string")
                elif not res.startswith('arn:aws:') and res != '*':
                    issues.append(f"Statement {index}: Invalid resource ARN '{res}'")

    def get_policy_size(self, policy: Dict[str, Any]) -> int:
        """Get policy size in characters"""
        return len(json.dumps(policy, separators=(',', ':')))

    def is_policy_too_large(self, policy: Dict[str, Any]) -> bool:
        """Check if policy exceeds AWS size limits"""
        # AWS managed policy limit is 6144 characters
        # Inline policy limit is 2048 characters
        return self.get_policy_size(policy) > 2048