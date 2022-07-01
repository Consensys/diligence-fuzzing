# Sample Brownie Project
## Description
It's purpose to create a brownie project environment to make unit tests upon. sample project is stored in `artifacts.tar.gz`.
## Notes
This sample project could be used as a standalone project to perform manual tests. In order to use it in standalone mode, please follow these steps:
1) Unpack the `artifacts.tar.gz` with `mkdir brownie-project && tar -xzvf artifacts.tar.gz --directory ./brownie-project && cd brownie-project`
2) Install Brownie
3) Add local network to deploy to already running ganache `brownie networks add development local host=http://localhost:7545 cmd=`
4) Compile project with `brownie compile`
5) Deploy project with `brownie run scripts/deploy.py --network local`
6) Have fun 🥳
