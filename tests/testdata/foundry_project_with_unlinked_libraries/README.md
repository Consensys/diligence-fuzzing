# Sample Foundry Project
## Description
It's purpose to create a foundry project environment to make unit tests upon. sample project is stored in `artifacts.tar.gz`.
## Notes
This sample project could be used as a standalone project to perform manual tests. In order to use it in standalone mode, please follow these steps:
1) Unpack the `artifacts.tar.gz` with `mkdir foundry-project && tar -xzvf artifacts.tar.gz --directory ./foundry-project && cd foundry-project`
2) Install foundry
3) Run `forge build --build-info` to compile contracts
4) Run `forge create <CONTRACT NAME> --unlocked --from <ACCOUNT> --legacy` to deploy contracts to a local ganache node.
    * You should deploy each contract separately, i.e. invoke this command 3 times with different contract names
    * `CONTRACT NAME` is the name of the contract to be deployed. In this case - the list `(ABC, Foo, Bar)`
    * `ACCOUNT` is one of the accounts Ganache creates at start (e.g. `0xDcD6A03FE66f8Ed4012554A6193819398Ba7495b`)
5) Have fun 🥳
