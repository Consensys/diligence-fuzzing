# History

0.11.1 (2023-05-04)
--------------------
- Add config sources (.env, ENV variables, config file) parsing
- Add Foundry tests list to submitted campaign
- Fix foundry tests build arguments to include metadata
- Add Smart Mode and Auto Fixes to `fuzz`

0.11.0 (2023-04-07)
--------------------
- Make `no-assert` mode default for `fuzz arm` command
- Drop support for Python 3.6
- Update dependencies
- Fix various bugs
- Improve error messages
- Remove `key` parameter from fuzzing config. Only `FUZZ_API_KEY` environment variable or `--key` command line argument is supported now.
- Finalize Foundry seamless integration

0.10.2 (2023-02-13)
--------------------
- Fix quickcheck campaigns bug

0.10.1 (2023-02-13)
--------------------
- Add block data to transactions in corpus

0.10.0 (2023-02-13)
--------------------
- Add foundry unit tests submission command (`fuzz forge test`)
- Fix contracts searching logic to use both metadata hash comparison and the whole bytecode comparison
- Provide map-to-original-source flag to the backend

0.9.17 (2023-01-11)
--------------------
- Fix metadata hash collection

0.9.16 (2023-01-09)
--------------------
- Fix artifacts processing for `Hardhat` and `Foundry` which led to an error

0.9.15 (2022-11-16)
--------------------
- Add new fuzzer options

0.9.14 (2022-11-09)
--------------------
- Add `version` command
- Fix artifacts collection for `Foundry` and `Hardhat`

0.9.13 (2022-11-08)
--------------------
- Fix sources directory detection bug in `generate-config` command

0.9.12 (2022-11-02)
--------------------
- Add `Foundry` framework support

0.9.11 (2022-09-29)
--------------------
- Fix large stdout handling for truffle db queries

0.9.10 (2022-09-07)
--------------------
- Add support for fuzzing limits related response codes

0.9.9 (2022-08-25)
--------------------
- Fix project parameter passing

0.9.8 (2022-08-25)
--------------------
- Fix fuzzing lessons logic

0.9.7 (2022-08-24)
--------------------
- Add `quickcheck` campaigns support
- Add support for the incremental fuzzing
- Add support for fuzzing lessons
- Fix various bugs

0.9.6 (2022-04-13)
--------------------
- Add `time_limit` config option

0.9.5 (2022-04-05)
--------------------
- Add option to provide truffle executable path
- Add proper debugging to truffle errors
- Include raw results to an error output for truffle projects

0.9.4 (2022-03-11)
--------------------
- Improve error messages display
- Make `no-assert` default option on config generator
- Improve api error handling for better error messages on subscriptions

0.9.3 (2022-03-08)
--------------------
- Add no subscription error message
- Improve error message for free trial
- Remove short form of corpus-target parameter at `fuzz run`
- Add additional checks for a seed state generator
- Add `--no-assert` flag to `scribble arm` command

0.9.2 (2022-02-22)
--------------------
- Fix bugs

0.9.1 (2022-02-22)
--------------------
- Add `requests` dependency to requirements
- Fix various bugs

0.9.0 (2022-02-10)
--------------------
- Add `generate-config` command
- Improve development frameworks support
- Add `dapptools` framework support

0.8.2 (2022-01-19)
--------------------
- Fix `disarm` command related bugs

0.8.1 (2021-10-26)
--------------------
- Fix bugs
- Improve `Hardhat` support

0.7.2 (2019-09-13)
--------------------
- Add new format API Key support
- Add `project_name` config parameter

0.7.1 (2019-09-13)
--------------------
- Update Readme

0.6.22 (2021-08-20)
--------------------
- First release on PyPI.
