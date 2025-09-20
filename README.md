# Lambda Analyzer

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A powerful static analysis tool that automatically infers AWS Lambda resource dependencies and generates optimal IAM policies from your Python code. Say goodbye to manually crafting complex SAM templates and overly permissive IAM policies.

## 🚀 Features

- **🔍 Smart Code Analysis**: Static analysis of Python Lambda functions to detect AWS service usage
- **🛡️ Least Privilege IAM**: Automatically generates minimal IAM policies based on actual API calls
- **📋 Template Generation**: Creates complete SAM/CloudFormation templates from code analysis
- **🎯 Resource Detection**: Identifies required AWS services, triggers, and environment variables
- **📊 Visual Reports**: Generates comprehensive analysis reports with recommendations
- **🔧 CLI & Python API**: Use as a command-line tool or integrate into your workflow

## 📦 Installation

```bash
pip install lambda-analyzer
```

Or install from source:

```bash
git clone https://github.com/DinoYu95/lambda-analyzer.git
cd lambda-analyzer
pip install -e .
```

## 🎯 Quick Start

### Analyze a Lambda Function

```bash
# Analyze a single Lambda function
lambda-analyzer analyze my_lambda.py

# Analyze entire project
lambda-analyzer analyze ./src --recursive

# Generate SAM template
lambda-analyzer generate-template --input ./src --output template.yaml
```

### Python API

```python
from lambda_analyzer import LambdaAnalyzer

analyzer = LambdaAnalyzer()
result = analyzer.analyze_file('my_lambda.py')

print(f"AWS Services detected: {result.services}")
print(f"IAM Policy: {result.iam_policy}")
```

## 📖 Usage Examples

### Example 1: Simple S3 Lambda

**Input Code** (`s3_handler.py`):
```python
import boto3
import json

def lambda_handler(event, context):
    s3_client = boto3.client('s3')
    
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']
    
    response = s3_client.get_object(Bucket=bucket, Key=key)
    content = response['Body'].read()
    
    return {
        'statusCode': 200,
        'body': json.dumps({'processed': True})
    }
```

**Generated Output**:
```bash
$ lambda-analyzer analyze multi_service.py

📊 Analysis Results for multi_service.py
=====================================

🔍 Detected AWS Services:
  • S3 (Simple Storage Service)

📡 Inferred Triggers:
  • S3 Event Notification (from event['Records'][0]['s3'])

🛡️ Required IAM Permissions:
  • s3:GetObject

📋 Generated IAM Policy:
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "*"
    }
  ]
}

💡 Recommendations:
  • Consider restricting S3 resource to specific buckets
  • Add error handling for missing objects
```

### Example 2: Multi-Service Lambda

**Input Code** (`multi_service.py`):
```python
import boto3
import os
from datetime import datetime

def lambda_handler(event, context):
    # DynamoDB operations
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ['TABLE_NAME'])
    
    # S3 operations  
    s3_client = boto3.client('s3')
    
    # SNS notifications
    sns_client = boto3.client('sns')
    
    # Process data
    item = {
        'id': event['user_id'],
        'timestamp': datetime.now().isoformat(),
        'data': event['data']
    }
    
    # DynamoDB write
    table.put_item(Item=item)
    
    # S3 backup
    s3_client.put_object(
        Bucket=os.environ['BACKUP_BUCKET'],
        Key=f"backup/{item['id']}.json",
        Body=str(item)
    )
    
    # Send notification
    sns_client.publish(
        TopicArn=os.environ['SNS_TOPIC'],
        Message=f"Processed user {event['user_id']}"
    )
    
    return {'statusCode': 200}
```

**Generated SAM Template**:
```bash
$ lambda-analyzer generate-template multi_service.py --format sam

# Generated template.yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31

Resources:
  MultiServiceFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: .
      Handler: multi_service.lambda_handler
      Runtime: python3.9
      Environment:
        Variables:
          TABLE_NAME: !Ref UserTable
          BACKUP_BUCKET: !Ref BackupBucket  
          SNS_TOPIC: !Ref NotificationTopic
      Policies:
        - DynamoDBWritePolicy:
            TableName: !Ref UserTable
        - S3WritePolicy:
            BucketName: !Ref BackupBucket
        - SNSPublishMessagePolicy:
            TopicName: !Ref NotificationTopic

  UserTable:
    Type: AWS::DynamoDB::Table
    Properties:
      # Table configuration will be prompted interactively
      
  BackupBucket:
    Type: AWS::S3::Bucket
    
  NotificationTopic:
    Type: AWS::SNS::Topic
```

## 🛠️ Configuration

Create a `.lambda-analyzer.yaml` configuration file in your project root:

```yaml
# Analysis settings
analysis:
  python_version: "3.9"
  include_patterns: ["*.py"]
  exclude_patterns: ["test_*.py", "tests/"]
  
# Template generation
template:
  format: sam  # sam, cloudformation, cdk
  runtime: python3.9
  timeout: 30
  memory: 512
  
# Resource configuration
resources:
  dynamodb:
    tables:
      - name: users-table
        hash_key: user_id
        hash_key_type: S
        billing_mode: PAY_PER_REQUEST
        
  s3:
    buckets:
      - name: backup-bucket
        versioning: true
        encryption: true
        
# IAM settings        
iam:
  least_privilege: true
  resource_constraints: true
```

## 🔧 Advanced Features

### Interactive Resource Configuration

```bash
# Launch interactive setup wizard
lambda-analyzer init

? What type of trigger does your Lambda use? S3 Event
? Which S3 bucket? my-source-bucket  
? What DynamoDB tables are used? users-table, sessions-table
? Configure table schema for users-table? Yes
  ? Primary key: user_id (String)
  ? Sort key: None
  ? Global Secondary Indexes? email-index
```

### Security Analysis

```bash
# Perform security analysis
lambda-analyzer security-check ./src

🔒 Security Analysis Results
===========================

⚠️  High Risk Issues:
  • Wildcard resource permissions detected in S3 policy
  • Missing encryption for DynamoDB table
  
⚡ Medium Risk Issues:  
  • Lambda function has overly broad IAM permissions
  
✅ Recommendations:
  • Specify exact S3 bucket ARNs instead of wildcards
  • Enable encryption at rest for DynamoDB
  • Use resource-based policies where possible
```

### Performance Insights

```bash
# Analyze performance implications
lambda-analyzer performance ./src

📈 Performance Analysis
======================

🚀 Optimization Opportunities:
  • Cold start: ~2.1s (boto3 client initialization)
  • Memory usage: Estimated 128MB (current allocation: 512MB)
  • Dependencies: 15 imports, 3 heavy libraries

💡 Recommendations:
  • Consider connection pooling for database clients
  • Use Lambda Layers for shared dependencies  
  • Reduce memory allocation to 256MB
  • Initialize clients outside handler for reuse
```

## 📚 API Reference

### LambdaAnalyzer Class

```python
from lambda_analyzer import LambdaAnalyzer

analyzer = LambdaAnalyzer(config_path='.lambda-analyzer.yaml')

# Analyze single file
result = analyzer.analyze_file('handler.py')

# Analyze directory
results = analyzer.analyze_directory('./src', recursive=True)

# Generate templates
template = analyzer.generate_template(
    results, 
    format='sam',
    output_path='template.yaml'
)
```

### AnalysisResult Object

```python
class AnalysisResult:
    file_path: str
    services: List[str]                    # ['s3', 'dynamodb', 'sns']
    api_calls: Dict[str, List[str]]        # {'s3': ['get_object', 'put_object']}
    iam_policy: Dict                       # Generated IAM policy JSON
    environment_variables: List[str]       # Required env vars
    triggers: List[Dict]                   # Inferred event sources
    security_issues: List[SecurityIssue]   # Potential security problems
    recommendations: List[str]             # Optimization suggestions
```

## 🧪 Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=lambda_analyzer --cov-report=html

# Type checking
mypy lambda_analyzer/

# Linting
black lambda_analyzer/ tests/
flake8 lambda_analyzer/ tests/
```

### Development Setup

```bash
# Clone repository
git clone https://github.com/DinoYu95/lambda-analyzer.git
cd lambda-analyzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Architecture Overview

```
lambda_analyzer/
├── core/
│   ├── analyzer.py          # Main analysis engine
│   ├── ast_parser.py        # Python AST parsing
│   ├── service_detector.py  # AWS service detection
│   └── policy_generator.py  # IAM policy generation
├── templates/
│   ├── sam.py              # SAM template generator
│   ├── cloudformation.py   # CloudFormation generator
│   └── cdk.py              # CDK generator  
├── cli/
│   ├── main.py             # CLI entry point
│   ├── commands/           # CLI command implementations
│   └── interactive.py      # Interactive wizards
├── utils/
│   ├── aws_mappings.py     # AWS API to IAM permission mappings
│   ├── patterns.py         # Common Lambda patterns
│   └── security.py         # Security analysis
└── tests/
    ├── fixtures/           # Test Lambda functions
    ├── unit/              # Unit tests
    └── integration/       # Integration tests
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- AWS SAM team for inspiration
- Chalice framework for IAM policy generation concepts  
- The Python AST module for making static analysis possible

## 📞 Support
- 📧 [Email Support](superdino950807@gmail.com)

---

**Made with ❤️ for the serverless community**