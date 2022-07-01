# Sample Dapptools Project
## Description
It's purpose to create a dapptools project environment to make unit tests upon. sample project is stored in `artifacts.tar.gz`.
## Notes
This sample project could be used as a standalone project to perform manual tests. In order to use it in standalone mode, please follow these steps:
1) Unpack the `artifacts.tar.gz` with `mkdir dapptools-project && tar -xzvf artifacts.tar.gz --directory ./dapptools-project && cd dapptools-project`
2) Install dapptools
3) Run `dapptools build` to compile contracts
4) Run `make deploy` to deploy contracts to a local ganache node
5) Have fun 🥳
