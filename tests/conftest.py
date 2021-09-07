import json
import logging
import os
from os import remove
from pathlib import Path

import pytest

from tests.common import get_test_case


def pytest_generate_tests(metafunc):
    os.environ["MYTHX_API_KEY"] = "test"
    for name in logging.root.manager.loggerDict:
        logging.getLogger(name).setLevel(logging.DEBUG)


@pytest.fixture()
def truffle_project(tmp_path, request):
    artifact = get_test_case("testdata/truffle-artifact.json")
    # switch to temp dir if requested
    if hasattr(request, "param") and request.param:
        os.chdir(str(tmp_path))

    # add truffle project structure
    os.makedirs(str(tmp_path / "build/contracts/MasterChefV2.sol/"))
    os.makedirs(str(tmp_path / "contracts"))

    with open("./truffle-config.js", "w+") as config_f:
        json.dump("sample", config_f)

    artifact["contractName"] = f"Foo"
    artifact["sourcePath"] = f"{tmp_path}/contracts/sample.sol"

    # add sample brownie artifact
    with open(tmp_path / "build/contracts/Foo.json", "w+") as artifact_f:
        json.dump(artifact, artifact_f)
    with open(tmp_path / "contracts/sample.sol", "w+") as sol_f:
        sol_f.write("sol code here")

    yield {"switch_dir": hasattr(request, "param") and request.param}
    os.remove(Path("./truffle-config.js").absolute())


@pytest.fixture()
def brownie_project(tmp_path):
    artifact = get_test_case("testdata/brownie-artifact.json")

    # add brownie project structure
    os.makedirs(str(tmp_path / "build/contracts/"))
    os.makedirs(str(tmp_path / "contracts/"))

    with open("./brownie-config.yaml", "w+") as config_f:
        json.dump("sample", config_f)

    # patch brownie artifact with temp path
    artifact["allSourcePaths"][0] = f"{tmp_path}/contracts/sample.sol"
    artifact["sourcePath"] = f"{tmp_path}/contracts/sample.sol"

    # add sample brownie artifact
    with open(tmp_path / "build/contracts/Foo.json", "w+") as artifact_f:
        json.dump(artifact, artifact_f)
    with open(tmp_path / "contracts/sample.sol", "w+") as sol_f:
        sol_f.write("sol code here")
    with open(tmp_path / "contracts/sample.sol.original", "w+") as sol_f:
        sol_f.write("original sol code here")

    yield None
    # cleaning up test files
    os.remove(str(Path("./brownie-config.yaml").absolute()))


@pytest.fixture()
def hardhat_project(tmp_path, request):
    artifact = get_test_case("testdata/hardhat-artifact.json")
    build_artifact = get_test_case("testdata/hardhat-build-info-artifact.json")

    # switch to temp dir if requested
    if hasattr(request, "param") and request.param:
        os.chdir(str(tmp_path))

    # add hardhat project structure
    os.makedirs(str(tmp_path / "artifacts/contracts/MasterChefV2.sol/"))
    os.makedirs(str(tmp_path / "artifacts/build-info/"))
    os.makedirs(str(tmp_path / "contracts"))

    # add sample brownie artifact
    with open(
        tmp_path / "artifacts/build-info/b78e6e91d6666dbbf407d4a383cd8177.json", "w+"
    ) as artifact_f:
        json.dump(build_artifact, artifact_f)

    with open("./hardhat.config.ts", "w+") as config_f:
        json.dump("sample", config_f)

    for filename, content in artifact.items():
        with open(
            tmp_path / f"artifacts/contracts/MasterChefV2.sol/{filename}.json", "w+"
        ) as sol_f:
            json.dump(content, sol_f)

    with open(tmp_path / "contracts/MasterChefV2.sol", "w+") as sol_f:
        sol_f.write("sol code here")

    with open(tmp_path / "contracts/sample.sol", "w+") as sol_f:
        sol_f.write("sol code here")

    with open(tmp_path / "contracts/MasterChefV2.sol.original", "w+") as sol_f:
        sol_f.write("original sol code here")

    with open(tmp_path / "contracts/sample.sol.original", "w+") as sol_f:
        sol_f.write("original sol code here")

    yield {"switch_dir": hasattr(request, "param") and request.param}

    os.remove(Path("./hardhat.config.ts").absolute())


@pytest.fixture(autouse=True)
def teardown():
    yield
    try:
        remove(".mythx.yml")
    except:
        pass
