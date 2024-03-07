# Configuration

The `fuzz` CLI tool allows configuration through 4 sources:

1. [YAML config file](#yaml-config-file)
2. [`.env` file](#env-file)
3. [Environment variables](#environment-variables)
4. [Command options](#command-options)

Each source has a different priority, based on the order in which they appear in the list. The sources with a lower priority are overridden by the ones with a higher priority. The order of precedence is as follows (from high to low priority):

1. Command options
2. Environment variables
3. `.env` file
4. YAML config file

## [General Configuration Options](#general-configuration-options)
| Variable          | Environment Variable   | Default Value | Type    | Description                                                                                                                                                                             |
|-------------------|------------------------|---------------|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `ci_mode`         | `FUZZ_CI_MODE`         | `False`       | `bool`  | CI mode toggle. In CI mode (i.e. `ci_mode = true`) any interactive prompts (to fix something or change something dynamically) will be disabled and default actions will be performed    |
| `report_crashes`  | `FUZZ_REPORT_CRASHES`  | `True`        | `bool`  | Switch to allow/disallow fuzzing-cli to send crash reports.                                                                                                                             |
| `allow_analytics` | `FUZZ_ALLOW_ANALYTICS` | `True`        | `bool`  | Switch to allow/disallow fuzzing-cli to send product usage analytics. Can also be turned off using `fuzz config set no-product-analytics` or on a prompt upon first campaign submission |

## [Fuzzing Configuration Options](#fuzzing-configuration-options)
| Variable                         | Environment Variable                  | Default Value             | Type                             | Description                                                                                                                   |
|----------------------------------|---------------------------------------|---------------------------|----------------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| `ide`                            | `FUZZ_IDE`                            | `None`                    | Optional `str`                   | The IDE that the project is using (e.g., `truffle`, `hardhat`). Usually, detected automatically                               |
| `build_directory`                | `FUZZ_BUILD_DIRECTORY`                | `None`                    | Optional `Path`                  | The path to the build directory of the project.                                                                               |
| `sources_directory`              | `FUZZ_SOURCES_DIRECTORY`              | `None`                    | Optional `Path`                  | The path to the sources directory of the project.                                                                             |
| `key`                            | `FUZZ_API_KEY`                        | `None`                    | Optional `str`                   | The API key used to submit campaigns to the Diligence Fuzzing API.                                                            |
| `smart_mode`                     | `FUZZ_SMART_MODE`                     | `False`                   | `bool`                           | Whether to use smart mode for the fuzzing campaign.                                                                           |
| `project`                        | `FUZZ_PROJECT`                        | `None`                    | Optional `str`                   | The name of the project to add submitted campaigns to                                                                         |
| `corpus_target`                  | `FUZZ_CORPUS_TARGET`                  | `None`                    | Optional `str`                   | The name of the corpus target to be used in the Diligence Fuzzing API.                                                        |
| `number_of_cores`                | `FUZZ_NUMBER_OF_CORES`                | `1`                       | `int`                            | The number of CPU cores to use for fuzzing.                                                                                   |
| `time_limit`                     | `FUZZ_TIME_LIMIT`                     | `None`                    | Optional `str`                   | The time limit for each individual fuzzing job (e.g., `10m`, `1h`, `30s`).                                                    |
| `targets`                        | `FUZZ_TARGETS`                        | `None`                    | Optional `List[str]`             | A list of Solidity files to be fuzzed.                                                                                        |
| `deployed_contract_address`      | `FUZZ_DEPLOYED_CONTRACT_ADDRESS`      | `None`                    | Optional `str`                   | The address of the deployed contract to be used in the fuzzing campaign.                                                      |
| `additional_contracts_addresses` | `FUZZ_ADDITIONAL_CONTRACTS_ADDRESSES` | `None`                    | Optional `Union[List[str], str]` | A list of additional contract addresses to be used in the fuzzing campaign (could be a string with comma-separated addresses) |
| `rpc_url`                        | `FUZZ_RPC_URL`                        | `"http://localhost:8545"` | `str`                            | The URL of the RPC node where the contract are deployed.                                                                      |
| `campaign_name_prefix`           | `FUZZ_CAMPAIGN_NAME_PREFIX`           | `"untitled"`              | `str`                            | The prefix to use for the name of the fuzzing campaign.                                                                       |
| `map_to_original_source`         | `FUZZ_MAP_TO_ORIGINAL_SOURCE`         | `False`                   | `bool`                           | Whether to map the generated inputs to the original source code.                                                              |
| `enable_cheat_codes`             | `FUZZ_ENABLE_CHEAT_CODES`             | `None`                    | Optional `bool`                  | Whether to enable cheat codes for the fuzzing campaign (`True` by default for foundry tests campaigns)                        |
| `chain_id`                       | `FUZZ_CHAIN_ID`                       | `None`                    | Optional `str`                   | The chain ID for the blockchain.                                                                                              |
| `incremental`                    | `FUZZ_INCREMENTAL`                    | `False`                   | `bool`                           | Whether to use incremental mode for the fuzzing campaign.                                                                     |
| `truffle_executable_path`        | `FUZZ_TRUFFLE_EXECUTABLE_PATH`        | `truffle`                 | Optional `str`                   | The path to the Truffle executable (for projects using the Truffle)                                                           |
| `dry_run`                        | `FUZZ_DRY_RUN`                        | `False`                   | `bool`                           | Whether to run the fuzzer in dry run mode when the campaign isn't submitted but the payload is outputted.                     |
| `max_sequence_length`            | `FUZZ_MAX_SEQUENCE_LENGTH`            | `None`                    | Optional `int`                   | Max sequence length (fuzzer parameter)                                                                                        |
| `ignore_code_hash`               | `FUZZ_IGNORE_CODE_HASH`               | `None`                    | Optional `bool`                  | Ignore code hash (fuzzer parameter)                                                                                           |

## [Arming Configuration Options](#arming-configuration-options)
| Variable         | Environment Variable     | Default Value | Type                 | Description                                                                                                   |
|------------------|--------------------------|---------------|----------------------|---------------------------------------------------------------------------------------------------------------|
| `solc_version`   | `ANALYZE_SOLC_VERSION`   | `None`        | Optional `str`       | The version of the Solidity compiler to use for analysis. If not specified, the default version will be used. |
| `remappings`     | `ANALYZE_REMAPPINGS`     | `[]`          | Optional `List[str]` | List of Solidity source path remappings in the form `from=to` separated by ";".                               |
| `scribble_path`  | `ANALYZE_SCRIBBLE_PATH`  | `"scribble"`  | Optional `str`       | Path to the Scribble binary.                                                                                  |
| `no_assert`      | `ANALYZE_NO_ASSERT`      | `True`        | `bool`               | If True, assertions will not be checked.                                                                      |
| `assert_`        | `ANALYZE_ASSERT`         | `False`       | `bool`               | If True, assertions will be checked.                                                                          |

## [Sources](#sources)
### YAML config file

YAML config file are a convenient way to store configuration parameters in a file. They can be provided as an argument to the `fuzz` command using the `-c` option. For example:

```
fuzz -c .fuzz.yml run
```

The YAML file should be structured as a dictionary, with the configuration parameters as keys and their values as values. For example:

```yaml
fuzz:
  smart_mode: true
  time_limit: 60
analyze:
  solc_version: 0.8.12
```

### `.env` file

`.env` files are used to set environment variables in a local development environment. They should be placed in the project's root directory and named `.env`. Each line in the file should contain a key-value pair, separated by an equal sign. They should be prefixed by `FUZZ_`. For example:

```
FUZZ_API_KEY=1234567890abcdef
FUZZ_SMART_MODE=1
ANALYZE_SOLC_VERSION=0.8.12
```

### Environment variables

Environment variables can be used to set configuration parameters for `fuzz`. They should be prefixed by `FUZZ_`. For example:

```
export FUZZ_API_KEY=1234567890abcdef
export FUZZ_SMART_MODE=1
export ANALYZE_SOLC_VERSION=0.8.12
```

### Command options

Each `fuzz` command has its own set of options that can be provided as command-line arguments. These options have the highest priority and override any other configuration source. For example:

```
fuzz run --map-to-original-source --smart-mode
```
or
```
fuzz arm --solc-version 0.8.12
```
