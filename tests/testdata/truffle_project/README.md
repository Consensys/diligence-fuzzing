# Sample Truffle Project
## Description
It's purpose to create a truffle project environment to make unit tests upon. sample project is stored in `artifacts.tar.gz`.
## Notes
This sample project could be used as a standalone project to perform manual tests. In order to use it in standalone mode, please follow these steps:
1) Unpack the `artifacts.tar.gz` with `mkdir truffle-project && tar -xzvf artifacts.tar.gz --directory ./truffle-project && cd truffle-project`
2) Install dependencies with `yarn install`
3) Install truffle globally with `yarn global add truffle`
4) Run `truffle compile` to compile contracts
5) Run `truffle migrate` to deploy contracts to a local ganache node
6) Have fun 🥳
