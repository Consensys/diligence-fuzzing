## Configuration

The commands of `fuzz` can be customized with yaml file (e.g. `.fuzz.yml`), `.env` file, environment variables or command arguments (e.g. `fuzz run --key <api key>`).

Below is a list of the environment variables recognized by `fuzz`.

| Variable                         | Environment Variable                  | Default                 | Synopsis                                                                                                                                           |
|----------------------------------|---------------------------------------|-------------------------| -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ide`                            | `FUZZ_IDE`                            | `None`                  | Directory for the project's Solidity contracts                                                                                                     |
| `build_directory`                | `FUZZ_BUILD_DIRECTORY`                | `None`                  | Directory for installed Dapp packages                                                                                                              |
| `sources_directory`              | `FUZZ_SOURCES_DIRECTORY`              | `None`                  | Directory for compilation artifacts                                                                                                                |
| `key`                            | `FUZZ_API_KEY`                        | `None`                  | Root directory of compilation                                                                                                                      |
| `project`                        | `FUZZ_PROJECT`                        | `None`                  | Solidity compiler version to use                                                                                                                   |
| `corpus_target`                  | `FUZZ_CORPUS_TARGET`                  | `None`                  | solc binary to use                                                                                                                                 |
| `number_of_cores`                | `FUZZ_NUMBER_OF_CORES`                | 1                       | Library addresses to link to                                                                                                                       |
| `time_limit`                     | `FUZZ_TIME_LIMIT`                     | `None`                  | Avoid compiling this time                                                                                                                          |
| `targets`                        | `FUZZ_TARGETS`                        | []                      | Print coverage data                                                                                                                                |
| `deployed_contract_address`      | `FUZZ_DEPLOYED_CONTRACT_ADDRESS`      | `None`                  | Compile with libraries                                                                                                                             |
| `additional_contracts_addresses` | `FUZZ_ADDITIONAL_CONTRACTS_ADDRESSES` | `None`                  | Attempt Etherscan verification                                                                                                                     |
| `rpc_url`                        | `FUZZ_RPC_URL`                        | `http://localhost:7545` | Set to `yes` to skip waiting for etherscan verification to succeed                                                                                 |
| `campaign_name_prefix`           | `FUZZ_CAMPAIGN_NAME_PREFIX`           | `untitled`              | [Solidity compilation options](https://docs.soliditylang.org/en/latest/using-the-compiler.html#compiler-input-and-output-json-description)         |
| `map_to_original_source`         | `FUZZ_MAP_TO_ORIGINAL_SOURCE`         | `False`                 | Set to `1` to output the default model checker settings when using `dapp mk-standard-json`. Running `dapp build` will invoke the SMTChecker.       |
| `enable_cheat_codes`             | `FUZZ_ENABLE_CHEAT_CODES`             | `None`                  | [Solidity remappings](https://docs.soliditylang.org/en/latest/using-the-compiler.html#path-remapping)                                              |
| `chain_id`                       | `FUZZ_CHAIN_ID`                       | `None`                  | Activate Solidity optimizer (`0` or `1`)                                                                                                           |
| `incremental`                    | `FUZZ_INCREMENTAL`                    | `False`                 | Set the optimizer runs                                                                                                                             |
| `truffle_executable_path`        | `FUZZ_TRUFFLE_EXECUTABLE_PATH`        | `truffle`               | Change compilation pipeline to go through the Yul intermediate representation (`0` or `1`)                                                         |
| `quick_check`                    | `FUZZ_QUICK_CHECK`                    | `False`                 | Only run test methods matching a regex                                                                                                             |
| `foundry_tests`                  | `FUZZ_FOUNDRY_TESTS`                  | `None`                  | Sets how much detail `dapp test` logs. Verbosity `1` shows traces for failing tests, `2` shows logs for all tests, `3` shows traces for all tests  |
| `target_contracts`               | `FUZZ_TARGET_CONTRACTS`               | `None`                  | How many iterations to use for each property test in your project                                                                                  |
| `dry_run`                        | `FUZZ_DRY_RUN`                        | `False`                 | Number of transactions to sequence per invariant cycle                                                                                             |
| `solc_version`                   | `ANALYZE_SOLC_VERSION`                | `None`                  | Timeout passed to the smt solver for symbolic tests (in ms, and per smt query)                                                                     |
| `remappings`                     | `ANALYZE_REMAPPINGS`                  | `[]`                    | The number of times hevm will revisit a particular branching point when symbolically executing                                                     |
| `scribble_path`                  | `ANALYZE_SCRIBBLE_PATH`               | `scribble`              | Solver to use for symbolic execution (`cvc4` or `z3`)                                                                                              |
| `no_assert`                      | `ANALYZE_NO_ASSERT`                   | `True`                  | Regex used to determine test methods to run                                                                                                        |
| `assert`                         | `ANALYZE_ASSERT`                      | `False`                 | Regex used to determine which files to print coverage reports for. Prints all imported files by default (excluding tests and libs).                |


```

### Precedence

There are multiple places to specify configuration options. They are read with the following precedence:

1. yaml config file
2. `.env` file
3. environment variables
4. command arguments

```

For a list of the supported `solc` versions, check [`solc-static-versions.nix`](/nix/solc-static-versions.nix).
