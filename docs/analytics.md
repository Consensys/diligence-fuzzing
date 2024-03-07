# Product Analytics Collection and Crash Reporting
This document describes how we collect and use [analytics](#analytics-report) and [crash data](#crash-report) in Fuzzing CLI.

## [Privacy Policy](#privacy-policy)
We take your privacy seriously. We do not collect any personal or sensitive information (except the ones you provide to us in the course of using the tool, e.g. your API key, contracts' source code). For more information, please read our [Privacy Policy](https://consensys.io/diligence/privacy-policy/).

## [Analytics Report](#analytics-report)
### Overview
Fuzzing CLI collects usage data to help us understand how the tool is being used and how we can improve it. We use this data to prioritize features and improvements. We do not collect any personal or sensitive information (except the ones you provide to us in the course of using the tool, e.g. your API key, contracts' source code). Here's what we collect:
- `deviceId` - a unique identifier for the current device (UUID v4)
- `sessionId` - a unique identifier for the current session (UUID v4)
- `system` - Name of the operating system (e.g. "Linux", "Windows", "Darwin")
- `release` - Version of the operating system (e.g. "23.0.0")
- `machine` - Machine type (e.g. "x86_64", "arm64")
- `pythonVersion` - Version of Python (e.g. "3.8.10")
- `pythonImplementation` - e.g. "CPython", "PyPy"
- `fuzzingCliVersion` - version of the tool
- `rpcNodeKind` - kind of the local rpc node (e.g. "truffle", "anvil", "ganache")
- `rpcNodeVersion` - version of the local rpc node
- `ciMode` - whether the tool is running in CI mode
- `userId` - a user identifier from the API key, if the user has provided it
- `functionCalls` - a list of function calls with the following fields:
  - `functionName` - the name of the function (e.g. "run", "arm")
  - `context` - additional context for the function call (e.g. parameters)
  - `result` - the result of the function call (e.g. "success", "exception")
  - `duration` - the duration of the command in milliseconds
  - `errorType` - the error type (*if the function call resulted in an exception*)
  - `errorMessage` - the error message (*if the function call resulted in an exception*)
  - `stackTrace` - the stack trace (*if the function call resulted in an exception*)

### Opting Out
You can opt out of analytics following ways:
1. At first run of the tool, you will be asked whether you want to opt out of analytics
   ```bash
    > Hey there! 👋 Mind if we collect some usage analytics?
    It helps us improve and make the experience better for you and others. 🚀.
    (You can revoke the consent at any time later using `fuzz config set no-product-analytics`) [Y/n]: n
    ```
2. By running `fuzz config set no-product-analytics` command
3. By setting `FUZZ_ALLOW_ANALYTICS` environment variable to `false`<br>
If you opt out, we will not collect any usage data from your device.<br>
> Note: [CI mode](configuration.md#general-configuration-options) will opt in to analytics by default, but you can opt out using the last two methods.

## [Crash Report](#crash-report)
### Overview
Fuzzing CLI collects crash data to help us understand and fix issues. We use this data to prioritize bug fixes. We do not collect any personal or sensitive information (except the ones you provide to us in the course of using the tool, e.g. your API key, contracts' source code). Here's what we collect:
- `deviceId` - a unique identifier for the current device (UUID v4)
- `sessionId` - a unique identifier for the current session (UUID v4)
- `system` - Name of the operating system (e.g. "Linux", "Windows", "Darwin")
- `release` - Version of the operating system (e.g. "23.0.0")
- `machine` - Machine type (e.g. "x86_64", "arm64")
- `pythonVersion` - Version of Python (e.g. "3.8.10")
- `pythonImplementation` - e.g. "CPython", "PyPy"
- `fuzzingCliVersion` - version of the tool
- `rpcNodeKind` - kind of the local rpc node (e.g. "truffle", "anvil", "ganache")
- `rpcNodeVersion` - version of the local rpc node
- `ciMode` - whether the tool is running in CI mode
- `userId` - a user identifier from the API key, if the user has provided it
- `context` - additional context for the function call (e.g. parameters)
- `errorType` - the error type (*if the function call resulted in an exception*)
- `errorMessage` - the error message (*if the function call resulted in an exception*)
- `errorCulprit` - the error culprit (*if the function call resulted in an exception*)
- `stackTrace` - the stack trace (*if the function call resulted in an exception*)
- `stackFrames` - the stack frames object (from python's traceback module) (*if the function call resulted in an exception*)

### Opting Out
You can opt out of crash data collection following ways:
1. At an every event of a crash, you will be asked whether you want to send the crash report. If you choose not to send the crash report, we will not collect any crash data from your device.
   ```bash
    > Oops! 🙊 Something didn't go as planned. Please see details below for more information:
    <Exception Type>: <Exception Message>
    Do you want to report this error? [Y/n]: n
    ```
2. By setting `FUZZ_REPORT_CRASHES` environment variable to `false`. Setting this environment variable will prevent the tool from asking you to send the crash report at every event of a crash.

> Note: [CI mode](configuration.md#general-configuration-options) will opt in to crash data collection by default, but you can opt out using the last method.

