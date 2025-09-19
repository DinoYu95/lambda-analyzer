"""
Lambda Analyzer - AWS Lambda static analysis tool

This package provides tools for analyzing AWS Lambda functions and automatically
generating IAM policies and infrastructure templates.
"""

__version__ = "1.0.0"
__author__ = "Dino Yu"
__email__ = "superdino950807@gmail.com"

from .core.analyzer import LambdaAnalyzer, AnalysisResult, SecurityIssue

__all__ = ["LambdaAnalyzer", "AnalysisResult", "SecurityIssue"]