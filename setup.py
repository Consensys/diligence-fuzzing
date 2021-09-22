#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import find_packages, setup

with open("README.rst") as readme_file:
    readme = readme_file.read()

with open("HISTORY.rst") as history_file:
    history = history_file.read()

with open("requirements.txt", "r") as f:
    requirements = [x for x in map(str.strip, f.read().split("\n")) if x != ""]

setup_requirements = ["pytest-runner"]

test_requirements = ["pytest"]

setup(
    author="Dominik Muhs, João Santos",
    author_email="joao.santos@consensys.net",
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Terminals :: Terminal Emulators/X Terminals",
        "Topic :: Utilities",
        "Typing :: Typed",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
    description="A command line interface for the Diligence Fuzzing API",
    entry_points={"console_scripts": ["fuzz=mythx_cli.cli:cli"]},
    install_requires=requirements,
    license="Apache-2.0 License",
    long_description=readme + "\n\n" + history,
    long_description_content_type="text/x-rst",
    include_package_data=True,
    keywords="diligence-fuzzing",
    name="diligence-fuzzing",
    packages=find_packages(exclude=["tests"]),
    setup_requires=setup_requirements,
    test_suite="tests",
    tests_require=test_requirements,
    url="https://github.com/ConsenSys/diligence-fuzzing",
    version="0.7.2",
    zip_safe=False,
)
