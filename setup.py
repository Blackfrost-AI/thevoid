#!/usr/bin/env python3
"""THE VOID — Setup script.

Operator-authorized AI red team — local, auditable, MCP-aware.
"""

from setuptools import setup, find_packages

setup(
    name="the-void",
    version="1.1.0",
    description="Operator-authorized AI red team — local, auditable, MCP-aware",
    author="Blackfrost AI",
    url="https://github.com/Blackfrost-AI/void_client",
    license="Apache-2.0",
    license_files=("LICENSE",),
    packages=find_packages(
        include=[
            "core*", "agent*", "orchestrator*", "recon*", "exploit*",
            "modules*", "c2*", "cli*", "config*", "llm*", "scenarios*",
            "commandcenter", "commandcenter.backend*",
        ],
        exclude=["tests*", "commandcenter.tests*", "commandcenter.scripts*"],
    ),
    python_requires=">=3.10",
    install_requires=[
        "python-dotenv>=1.0.0",
        "requests>=2.31.0",
        "urllib3>=2.7.0",
        "cryptography>=50.0.1",
        "sqlalchemy>=2.0.0",
        "pyyaml>=6.0.0",
        "toml>=0.10.0",
        "loguru>=0.7.0",
        "click==8.1.8",  # 8.2+ removes CliRunner(mix_stderr=...); matches runtime lock
        "rich>=13.5.0",
        "httpx>=0.25.0",
        "dnspython>=2.4.0",
        "schedule>=1.2.0",
        "tqdm>=4.66.0",
        "colorama>=0.4.6",
        "fastapi>=0.110.0",
        "uvicorn>=0.27.0",
        "wsproto>=1.3.2",
        "pydantic>=2.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-asyncio>=0.21.0",
            "pytest-timeout>=2.3.0",
            "ruff>=0.11.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "mypy>=1.5.0",
            "flake8>=6.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "void=run:main",
            "thevoid=cli.app:main",
            "thevoid-command-center=commandcenter.launcher:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
)
