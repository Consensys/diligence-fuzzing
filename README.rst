====================================
A CLI for the Diligence Fuzzing API
====================================

This package aims to provide a simple to use command line interface for the `Diligence Fuzzing <https://consensys.net/diligence/fuzzing/>`_ smart contract
security analysis API.


What is Diligence Fuzzing?
--------------------------

Easy to use and powerful, Fuzzing as a Service enables users to find bugs immediately after writing their first specification!
Smart contracts are increasingly complex programs that often hold and manage large amounts of assets. Developers should use tools to analyze their smart contracts before deploying them to find vulnerabilities open to exploitation.


Usage
-----

.. code-block:: console

    $ Usage: fuzz [OPTIONS] COMMAND [ARGS]...

    Your CLI for interacting with https://fuzzing.diligence.tools

    Options:
      --debug            Provide additional debug output
      -c, --config PATH  YAML config file for default parameters
      --help             Show this message and exit.

    Commands:
      arm              Prepare the target files for Diligence Fuzzing API...
      auto             Automatically annotate test contracts
      disarm           Revert the target files to their original,...
      generate-config  Generate config file for fuzzing
      lesson           Manage fuzzing lessons
      run              Submit contracts to the Diligence Fuzzing API



Installation
------------

The Diligence Fuzzing CLI runs on Python 3.6+, including 3.8 and pypy3.

To get started, simply run

.. code-block:: console

    $ pip3 install diligence-fuzzing

Alternatively, clone the repository and run

.. code-block:: console

    $ pip3 install .

Or directly through Python's :code:`setuptools`:

.. code-block:: console

    $ python3 setup.py install


* Free software: Apache 2 license
* Documentation: https://fuzzing-docs.diligence.tools/getting-started/configuring-the-cli
