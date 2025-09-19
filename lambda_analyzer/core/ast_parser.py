"""
AST Parser for analyzing Python Lambda code structure
"""

import ast
from typing import Dict, List, Set, Optional


class ASTAnalyzer(ast.NodeVisitor):
    """
    AST visitor for extracting AWS service usage patterns from Python code

    This class walks through the Abstract Syntax Tree (AST) of Python code
    to identify patterns related to AWS service usage, such as:
    - boto3 client/resource creation
    - AWS API method calls
    - Environment variable access
    - Lambda event structure access
    """

    def __init__(self):
        # Import tracking
        self.imports: Dict[str, str] = {}  # alias -> full_import_path

        # AWS service tracking
        self.service_clients: Dict[str, Dict[str, str]] = {}  # var_name -> service_info
        self.api_calls: Dict[str, Set[str]] = {}  # service -> set_of_methods

        # Environment and configuration
        self.environment_variables: Set[str] = set()

        # Lambda-specific patterns
        self.event_accesses: List[str] = []  # event access patterns
        self.context_accesses: List[str] = []  # context access patterns

        # Code structure info
        self.function_names: Set[str] = set()
        self.class_names: Set[str] = set()
        self.string_literals: List[str] = []

        # Control flow
        self.has_try_except: bool = False
        self.has_error_handling: bool = False

    def visit_Import(self, node: ast.Import) -> None:
        """Track import statements like 'import boto3'"""
        for alias in node.names:
            import_name = alias.asname or alias.name
            self.imports[import_name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track from imports like 'from boto3 import client'"""
        if node.module:
            for alias in node.names:
                import_name = alias.asname or alias.name
                full_path = f"{node.module}.{alias.name}"
                self.imports[import_name] = full_path
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Track function definitions"""
        self.function_names.add(node.name)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Track async function definitions"""
        self.function_names.add(node.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Track class definitions"""
        self.class_names.add(node.name)
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        """Track try/except blocks for error handling analysis"""
        self.has_try_except = True
        # Check if it's handling AWS-related exceptions
        for handler in node.handlers:
            if handler.type:
                if isinstance(handler.type, ast.Name):
                    if 'error' in handler.type.id.lower() or 'exception' in handler.type.id.lower():
                        self.has_error_handling = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """
        Track function calls, especially boto3 client creation and AWS API calls
        """
        call_string = self._get_call_string(node)

        # Track boto3 client/resource creation
        if self._is_boto3_client_creation(call_string, node):
            self._handle_boto3_client_creation(node, call_string)

        # Track API method calls on AWS service clients
        elif self._is_aws_api_call(node):
            self._handle_aws_api_call(node)

        # Track os.environ access
        elif self._is_environ_access(call_string, node):
            self._handle_environ_access(node)

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """
        Track subscript operations like event['key'] or os.environ['VAR']
        """
        subscript_string = self._get_subscript_string(node)

        # Track event access patterns for trigger detection
        if subscript_string and 'event[' in subscript_string:
            self.event_accesses.append(subscript_string)

        # Track context access patterns
        elif subscript_string and 'context[' in subscript_string:
            self.context_accesses.append(subscript_string)

        # Track os.environ['KEY'] access
        elif self._is_environ_subscript(node):
            self._handle_environ_subscript(node)

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Track attribute access like obj.method"""
        # This is handled in visit_Call for method calls
        # But we can track other attribute access patterns here
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        """Track string constants for pattern analysis"""
        if isinstance(node.value, str) and len(node.value) > 2:
            self.string_literals.append(node.value)
        self.generic_visit(node)

    def visit_Str(self, node: ast.Str) -> None:
        """Track string literals (for older Python versions)"""
        if len(node.s) > 2:
            self.string_literals.append(node.s)
        self.generic_visit(node)

    def _get_call_string(self, node: ast.Call) -> str:
        """Convert a call AST node to string representation"""
        try:
            if isinstance(node.func, ast.Name):
                return node.func.id
            elif isinstance(node.func, ast.Attribute):
                obj_name = self._get_object_name(node.func.value)
                return f"{obj_name}.{node.func.attr}" if obj_name else node.func.attr
        except:
            pass
        return ""

    def _get_object_name(self, node: ast.AST) -> Optional[str]:
        """Extract object name from AST node"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            obj_name = self._get_object_name(node.value)
            return f"{obj_name}.{node.attr}" if obj_name else node.attr
        return None

    def _get_subscript_string(self, node: ast.Subscript) -> Optional[str]:
        """Convert subscript access to string for pattern matching"""
        try:
            if isinstance(node.value, ast.Name):
                if isinstance(node.slice, ast.Constant):
                    return f"{node.value.id}['{node.slice.value}']"
                elif isinstance(node.slice, ast.Str):  # Older Python
                    return f"{node.value.id}['{node.slice.s}']"
        except:
            pass
        return None

    def _is_boto3_client_creation(self, call_string: str, node: ast.Call) -> bool:
        """Check if this is a boto3 client or resource creation call"""
        return (
                'boto3.client' in call_string or
                'boto3.resource' in call_string or
                (call_string in ['client', 'resource'] and
                 any('boto3' in imp for imp in self.imports.values()))
        )

    def _is_aws_api_call(self, node: ast.Call) -> bool:
        """Check if this is an AWS API method call"""
        if isinstance(node.func, ast.Attribute):
            obj_name = self._get_object_name(node.func.value)
            return obj_name in self.service_clients
        return False

    def _is_environ_access(self, call_string: str, node: ast.Call) -> bool:
        """Check if this is os.environ.get() call"""
        return 'os.environ.get' in call_string or call_string == 'getenv'

    def _is_environ_subscript(self, node: ast.Subscript) -> bool:
        """Check if this is os.environ['KEY'] access"""
        if isinstance(node.value, ast.Attribute):
            return (
                    isinstance(node.value.value, ast.Name) and
                    node.value.value.id == 'os' and
                    node.value.attr == 'environ'
            )
        return False

    def _handle_boto3_client_creation(self, node: ast.Call, call_string: str) -> None:
        """Handle boto3 client/resource creation"""
        if node.args and isinstance(node.args[0], (ast.Constant, ast.Str)):
            # Extract service name
            if isinstance(node.args[0], ast.Constant):
                service_name = node.args[0].value
            else:  # ast.Str for older Python
                service_name = node.args[0].s

            # Find the variable name this is being assigned to
            var_name = self._find_assignment_target(node)
            if var_name:
                self.service_clients[var_name] = {
                    'service': service_name,
                    'type': 'client' if 'client' in call_string else 'resource'
                }

    def _handle_aws_api_call(self, node: ast.Call) -> None:
        """Handle AWS API method calls"""
        if isinstance(node.func, ast.Attribute):
            obj_name = self._get_object_name(node.func.value)
            method_name = node.func.attr

            if obj_name in self.service_clients:
                service_info = self.service_clients[obj_name]
                service = service_info['service']

                if service not in self.api_calls:
                    self.api_calls[service] = set()
                self.api_calls[service].add(method_name)

    def _handle_environ_access(self, node: ast.Call) -> None:
        """Handle os.environ.get() calls"""
        if node.args and isinstance(node.args[0], (ast.Constant, ast.Str)):
            if isinstance(node.args[0], ast.Constant):
                env_var = node.args[0].value
            else:  # ast.Str for older Python
                env_var = node.args[0].s
            self.environment_variables.add(env_var)

    def _handle_environ_subscript(self, node: ast.Subscript) -> None:
        """Handle os.environ['KEY'] subscript access"""
        if isinstance(node.slice, (ast.Constant, ast.Str)):
            if isinstance(node.slice, ast.Constant):
                env_var = node.slice.value
            else:  # ast.Str for older Python
                env_var = node.slice.s
            self.environment_variables.add(env_var)

    def _find_assignment_target(self, node: ast.Call) -> Optional[str]:
        """
        Find the variable name that a call is being assigned to
        This is a simplified version - a full implementation would handle
        more complex assignment patterns
        """
        # Walk up the AST to find assignment
        current = node
        while hasattr(current, 'parent'):
            parent = current.parent
            if isinstance(parent, ast.Assign):
                # Simple assignment like: client = boto3.client('s3')
                if parent.targets and isinstance(parent.targets[0], ast.Name):
                    return parent.targets[0].id
            elif isinstance(parent, ast.AnnAssign):
                # Annotated assignment like: client: boto3.Client = boto3.client('s3')
                if isinstance(parent.target, ast.Name):
                    return parent.target.id
            current = parent
        return None