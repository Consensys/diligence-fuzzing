# A CLI for the Diligence Fuzzing API
This package aims to provide a simple to use command line interface for the [Diligence Fuzzing](https://consensys.net/diligence/fuzzing/) smart contract
security analysis API.

# What is Diligence Fuzzing?
Easy to use and powerful, Fuzzing as a Service enables users to find bugs immediately after writing their first specification!
Smart contracts are increasingly complex programs that often hold and manage large amounts of assets. Developers should use tools to analyze their smart contracts before deploying them to find vulnerabilities open to exploitation.

# Getting Started
If you're new to the Diligence Fuzzing tool or want to learn more about its capabilities, the 📚 [Fuzzing Docs](https://fuzzing-docs.diligence.tools/) is a great resource to get started.

These docs contain detailed instructions on how to configure the tool, best practices for integrating it into your development workflow, and more. You'll also find sample projects to help you test the Fuzzing CLI and get up to speed quickly. Whether you're just starting out or an experienced user, the 📚 [Fuzzing Docs](https://fuzzing-docs.diligence.tools/) have everything you need to make the most of the Diligence Fuzzing tool.

Table of Contents
=================

  - [Installing](#installing)
  - [Basic Usage](#basic-usage)
    - [Arm contracts](#arm-contracts)
    - [Disarm contracts](#disarm-contracts)
    - [Smart Mode](#smart-mode)
    - [Manual Mode](#manual-mode)
    - [Foundry Tests](#foundry-tests)
  - [Configuration](#configuration)
  - [Commands](#commands)

## Installing
The Diligence Fuzzing CLI runs on Python 3.7+, including PyPy.

To get started, simply run

```console
$ pip3 install diligence-fuzzing
```

Alternatively, clone the repository and run

```console
$ pip3 install .
```
Or directly through Python's :code:`setuptools`:
```console
$ python3 setup.py install
```
> Don't forget to add the directory containing the `fuzz` executable to your system's PATH environment variable.

# Basic Usage
Fuzz is a command-line tool for smart contract fuzzing. It provides several modes of fuzzing, including smart mode, manual mode, and Foundry tests fuzzing.

## Create a configuration file

To automatically generate a configuration file run `fuzz config generate`. You will then be guided through a process to get you going.

## Arm contracts

`fuzz arm` is a command in the Diligence Fuzzing Toolset that instruments Solidity code with Scribble, a runtime verification tool, for property-based testing. This command runs `scribble --arm ...` on the given target files, instrumenting their code in-place with Scribble.

### 1. Annotate contracts

Before running `fuzz arm`, you need to annotate some code in a Solidity file using Scribble annotations. Here is an example:

   ```
   /// #if_succeeds {:msg "Transfer does not modify the sum of balances" } old(_balances[_to]) + old(_balances[msg.sender]) == _balances[_to] + _balances[msg.sender];
   function transfer(address _to, uint256 _value) external returns (bool) {
       ...
   }
   ```

   For more information on Scribble annotations, please refer to the [Scribble exercise repository](https://github.com/ConsenSys/scribble-exercise-1).


### 2. Running the Command

Run the `fuzz arm` command, followed by the path to the target file(s) or directory(ies).

   ```
   fuzz arm path/to/target_file.sol path/to/another_target_file.sol path/to/contracts
   ```
   > You can also provide targets in the [Config](#configuration)

The `fuzz arm` command will instrument the target file(s) with Scribble in-place, creating a backup of the original file(s) in a `.original` file.

### 3. Fuzz
Once you have run `fuzz arm` and have completed the testing process, you can fuzz the annotated contracts using either [Smart Mode](#smart-mode) or [Manual Mode](#manual-mode).

> You can also use the [`fuzz disarm` command](#disarm-contracts) to revert the target file(s) to their original, un-instrumented state.

## Disarm contracts

The `fuzz disarm` command reverts the target files to their original, un-instrumented state using the Scribble tool for Solidity runtime verification.

To run `fuzz disarm`, you should:

1. Have previously run the `fuzz arm` command on the target files.

2. Navigate to the directory where the target files are located.

3. Run the following command:

   ```
   fuzz disarm <target_files>
   ```

   Replace `<target_files>` with the path to the Solidity files that you want to revert to their original state.

   **Note:** If you do not provide any target files, the `fuzz disarm` command will run on all Solidity files in the current directory and its subdirectories.

After running `fuzz disarm`, the target files will be reverted to their original, un-instrumented state.

## Smart Mode

In this mode, fuzzing cli automatically collects all contracts in your project and submits campaigns to the Fuzzing API. To use smart mode, follow these steps:

### 1. Deploy Contracts

After installing `diligence-fuzzing`, you need to deploy your contracts to the RPC node. Depending on your IDE, there are different ways to deploy contracts. Here are some resources for different IDEs:

- Truffle: https://www.trufflesuite.com/docs/truffle/getting-started/running-migrations
- Dapptools: https://dapphub.com/guides/brownie-fundamentals/deploy-a-contract/
- Hardhat: https://hardhat.org/tutorial/deploying-to-a-live-network.html
- Brownie: https://eth-brownie.readthedocs.io/en/latest/deployment.html#deploying-to-a-public-network
- Foundry: https://docs.foundry.build/foundry-cli/#deploying-a-contract

### 2. Set API Key

To use Fuzz, you need to obtain an API key from https://consensys.net/diligence/fuzzing/. Once you have obtained an API key, you need to set it as an environment variable:

```bash
export FUZZ_API_KEY=<your_api_key>
```

### 3. Enable Smart Mode

Smart Mode will be enabled by default when you use the configuration generator. To enable Smart Mode manually, you need to set the `SMART_MODE` environment variable:

```bash
export FUZZ_SMART_MODE=1
```

For more information on Smart Mode and its configuration options, refer to the documentation.

### 4. Run Fuzz

Once you have deployed your contracts and set the appropriate environment variables, you can use `fuzz run` to start fuzzing your contracts:

```bash
fuzz run
```

## Manual Mode

Manual Mode is the default mode for Fuzz. Manual mode requires you to specify the target contracts and the addresses of the contracts under test. This mode can be useful if you want to fuzz specific contracts and test them against specific addresses. To use manual mode, follow these steps:

### 1. Deploy Contracts

You need to deploy your contracts to the RPC node. Depending on your IDE, there are different ways to deploy contracts. Here are some resources for different IDEs:

- Truffle: https://www.trufflesuite.com/docs/truffle/getting-started/running-migrations
- Dapptools: https://dapphub.com/guides/brownie-fundamentals/deploy-a-contract/
- Hardhat: https://hardhat.org/tutorial/deploying-to-a-live-network.html
- Brownie: https://eth-brownie.readthedocs.io/en/latest/deployment.html#deploying-to-a-public-network
- Foundry: https://docs.foundry.build/foundry-cli/#deploying-a-contract

### 2. Configure targets
First, you need to specify the targets for fuzzing. The targets are the source file paths of the contracts to be fuzzed. For example,
you can specify the targets in a YAML file:

```yaml
    fuzz:
      targets:
        - contracts/MyContract.sol
        - contracts/MyOtherContract.sol
```

### 3. Configure addresses under test
Second, you need to specify the addresses of the contracts under test. The addresses are the addresses of the deployed contracts on the RPC node. For example,
you can specify the addresses in a YAML file:

```yaml
    fuzz:
      deployed_contract_address: 0x1234567890123456789012345678901234567890
      additional_contracts_addresses:
        - 0x1234567890123456789012345678901234567890
        - 0x0987654321098765432109876543210987654321
```

### 4. Set API Key

To use Fuzz, you need to obtain an API key from https://consensys.net/diligence/fuzzing/. Once you have obtained an API key, you need to set it as an environment variable:

```bash
export FUZZ_API_KEY=<your_api_key>
```

For more information on Manual mode and its options, refer to the documentation.

### 5. Run Fuzz

Once you have deployed your contracts and set the appropriate environment variables, you can use `fuzz run` to start fuzzing your contracts:

```bash
fuzz run
```

## Foundry Tests

Fuzz provides a mode to automatically collect all Foundry unit tests from the project and submit a campaign without deploying them to the RPC node. To use the Foundry test fuzzing mode, follow these steps:

1. Set a `FUZZ_API_KEY` environment variable. You can obtain a free account from https://consensys.net/diligence/fuzzing/.
2. Navigate to the root directory of your project.
3. Run the following command:

   ```bash
   fuzz forge test
   ```

   This will automatically collect all Foundry unit tests from the project and submit a campaign without deploying them to the RPC node.

For more information on Foundry test fuzzing and its options, refer to the documentation.

## Configuration

The `fuzz` CLI tool allows configuration through 4 sources:

1. YAML config files
2. `.env` files
3. Environment variables
4. Command options

Consult the documentation for each command to learn about the available options.
For more information on `fuzz` configuration, refer to the [Configuration](docs/configuration.md) documentation.


## Commands
The `fuzz` CLI tool provides the following commands:
- `arm`: Prepares the target files for Diligence Fuzzing API submission.
- `auto`: Automatically annotates test contracts.
- `config`: Manages diligence-fuzzing configuration.
- `disarm`: Reverts the target files to their original, un-instrumented state.
- `forge`: Submits foundry unit tests to fuzzing.
- `lesson`: Manages fuzzing lessons.
- `run`: Submits contracts to the Diligence Fuzzing API.
- `version`: Shows diligence-fuzzing version.

Each command serves a specific purpose in the fuzzing process, and they can be used together to configure and execute fuzzing campaigns. For more information on each command, consult the corresponding documentation.


* Free software: Apache 2 license
