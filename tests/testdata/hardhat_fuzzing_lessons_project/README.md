# Sample Hardhat Project
## Description
It's purpose to create a hardhat project environment to make unit tests upon. sample project is stored in `artifacts.tar.gz`.
## Notes
This sample project could be used as a standalone project to perform manual tests. In order to use it in standalone mode, please follow these steps:
1) Unpack the `artifacts.tar.gz` with `mkdir hardhat-project && tar -xzvf artifacts.tar.gz --directory ./hardhat-project && cd hardhat-project`
2) Install dependencies with `yarn install`
3) Run `npx hardhat compile` to compile contracts
4) Run `npx hardhat run scripts/deploy.js` to deploy contracts to a local ganache node
5) Have fun 🥳

## Few words on Fuzzing Lessons
This project contains script (`scripts/run_lesson.js`) to submit transactions which lead to revert. You may not need it, but here's the explanation - These transactions are to help Harvey find an issue (that's why we name it Fuzzing Lessons)
