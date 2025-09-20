from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="lambda-analyzer",
    version="1.0.0",
    author="Dino Yu",
    author_email="superdino950807@gmail.com",
    description="AWS Lambda static analysis tool for resource dependency detection and IAM policy generation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/DinoYu95/lambda-analyzer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "PyYAML>=6.0",
        "rich>=12.0.0",
        "click>=8.0.0",
        "boto3>=1.26.0"
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.991",
            "pre-commit>=2.20.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "lambda-analyzer=lambda_analyzer.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "lambda_analyzer": ["templates/*.yaml", "config/*.yaml"],
    },
)