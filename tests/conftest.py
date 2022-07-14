import json
import os
import tarfile
from os import remove
from pathlib import Path

import pytest

from tests.common import get_test_case


@pytest.fixture()
def truffle_project(tmp_path, request):
    artifact = get_test_case("testdata/truffle-artifact.json")
    # switch to temp dir if requested
    if hasattr(request, "param") and request.param:
        os.chdir(str(tmp_path))

    # add truffle project structure
    os.makedirs(str(tmp_path / "build/contracts/MasterChefV2.sol/"))
    os.makedirs(str(tmp_path / "contracts"))

    # we create the config file NOT in the temp directory, but in the CWD because it's where pytest
    # is running and looking for the file. At the end of the test we delete the file
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

    # we create the config file NOT in the temp directory, but in the CWD because it's where pytest
    # is running and looking for the file. At the end of the test we delete the file
    with open("brownie-config.yaml", "w+") as config_f:
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
    os.remove(Path("brownie-config.yaml").absolute())


@pytest.fixture()
def dapptools_project(tmp_path):
    original_artifact = get_test_case("testdata/dapptools_artifact.json")

    # add dapptools project structure
    os.makedirs(str(tmp_path / "out/"))
    os.makedirs(str(tmp_path / "src/test/utils/"))
    os.makedirs(str(tmp_path / "lib/openzeppelin-contracts/contracts/utils/"))
    os.makedirs(str(tmp_path / "lib/openzeppelin-contracts/contracts/access/"))
    os.makedirs(str(tmp_path / "lib/ds-test/src/"))

    # create dapptools config file
    # we create the config file NOT in the temp directory, but in the CWD because it's where pytest
    # is running and looking for the file. At the end of the test we delete the file
    with open(".dapprc", "w+") as config_f:
        json.dump("sample", config_f)

    # patch dapptools artifact with temp path
    artifact = {"sources": {}, "contracts": {}}
    for k, v in original_artifact["sources"].items():
        artifact["sources"][f"{tmp_path}/{k}"] = v
    for k, v in original_artifact["contracts"].items():
        artifact["contracts"][f"{tmp_path}/{k}"] = v

    # Create a temp dapptools artifacts file with the patched locations
    with open(tmp_path / "out/dapp.sol.json", "w+") as artifact_f:
        json.dump(artifact, artifact_f)
    # Create the temp solidity files
    for k, v in artifact["contracts"].items():
        with open(k, "w+") as sol_f:
            sol_f.write("sol code here")
        with open(k + ".original", "w+") as original_sol_f:
            original_sol_f.write("original sol code here")

    yield None
    os.remove(Path(".dapprc").absolute())


@pytest.fixture()
def hardhat_project(tmp_path, request):
    artifact = get_test_case("testdata/hardhat-artifact.json")
    different_contracts_artifact = get_test_case(
        "testdata/hardhat-artifact-different-contract-name.json"
    )
    build_artifact = get_test_case("testdata/hardhat-build-info-artifact.json")
    build_artifact_1 = get_test_case("testdata/hardhat-build-info-artifact-1.json")

    # switch to temp dir if requested
    if hasattr(request, "param") and request.param:
        os.chdir(str(tmp_path))

    # add hardhat project structure
    os.makedirs(str(tmp_path / "artifacts/contracts/MasterChefV2.sol/"))
    os.makedirs(str(tmp_path / "artifacts/contracts/sample.sol/"))
    os.makedirs(str(tmp_path / "artifacts/build-info/"))
    os.makedirs(str(tmp_path / "contracts"))

    # add sample brownie artifact
    with open(
        tmp_path / "artifacts/build-info/b78e6e91d6666dbbf407d4a383cd8177.json", "w+"
    ) as artifact_f:
        json.dump(build_artifact, artifact_f)

    with open(
        tmp_path / "artifacts/build-info/1971e920b375c86605b83cbedee1f092.json", "w+"
    ) as artifact_f:
        json.dump(build_artifact_1, artifact_f)

    with open("./hardhat.config.ts", "w+") as config_f:
        json.dump("sample", config_f)

    for filename, content in artifact.items():
        with open(
            tmp_path / f"artifacts/contracts/MasterChefV2.sol/{filename}.json", "w+"
        ) as sol_f:
            json.dump(content, sol_f)

    for filename, content in different_contracts_artifact.items():
        with open(
            tmp_path / f"artifacts/contracts/sample.sol/{filename}.json", "w+"
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


@pytest.fixture()
def isolated_hardhat_project(tmp_path):
    artifact = get_test_case("testdata/hardhat-artifact.json")
    different_contracts_artifact = get_test_case(
        "testdata/hardhat-artifact-different-contract-name.json"
    )
    build_artifact = get_test_case("testdata/hardhat-build-info-artifact.json")
    build_artifact_1 = get_test_case("testdata/hardhat-build-info-artifact-1.json")

    # add hardhat project structure
    os.makedirs(str(tmp_path / "artifacts/contracts/MasterChefV2.sol/"))
    os.makedirs(str(tmp_path / "artifacts/contracts/sample.sol/"))
    os.makedirs(str(tmp_path / "artifacts/build-info/"))
    os.makedirs(str(tmp_path / "contracts"))

    # add sample brownie artifact
    with open(
        tmp_path / "artifacts/build-info/b78e6e91d6666dbbf407d4a383cd8177.json", "w+"
    ) as artifact_f:
        json.dump(build_artifact, artifact_f)

    with open(
        tmp_path / "artifacts/build-info/1971e920b375c86605b83cbedee1f092.json", "w+"
    ) as artifact_f:
        json.dump(build_artifact_1, artifact_f)

    with open(f"{tmp_path}/hardhat.config.ts", "w+") as config_f:
        json.dump("sample", config_f)

    for filename, content in artifact.items():
        with open(
            tmp_path / f"artifacts/contracts/MasterChefV2.sol/{filename}.json", "w+"
        ) as sol_f:
            json.dump(content, sol_f)

    for filename, content in different_contracts_artifact.items():
        with open(
            tmp_path / f"artifacts/contracts/sample.sol/{filename}.json", "w+"
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


@pytest.fixture()
def isolated_brownie_project(tmp_path):
    artifact = get_test_case("testdata/brownie-artifact.json")

    # add brownie project structure
    os.makedirs(str(tmp_path / "build/contracts/"))
    os.makedirs(str(tmp_path / "contracts/"))

    with open(f"{tmp_path}/brownie-config.yaml", "w+") as config_f:
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


@pytest.fixture()
def isolated_truffle_project(tmp_path):
    artifact = get_test_case("testdata/truffle-artifact.json")

    # add truffle project structure
    os.makedirs(str(tmp_path / "build/contracts/MasterChefV2.sol/"))
    os.makedirs(str(tmp_path / "contracts"))

    with open(f"{tmp_path}/truffle-config.js", "w+") as config_f:
        json.dump("sample", config_f)

    artifact["contractName"] = "Foo"
    artifact["sourcePath"] = f"{tmp_path}/contracts/sample.sol"

    # add sample brownie artifact
    with open(tmp_path / "build/contracts/Foo.json", "w+") as artifact_f:
        json.dump(artifact, artifact_f)
    with open(tmp_path / "contracts/sample.sol", "w+") as sol_f:
        sol_f.write("sol code here")


@pytest.fixture()
def bootstrapped_truffle_project(tmp_path):
    with tarfile.open(
        Path(__file__).parent.joinpath(
            "testdata", "truffle_project", "artifacts.tar.gz"
        )
    ) as f:
        f.extractall(tmp_path)

    for artifact_path in Path(tmp_path).joinpath("build", "contracts").glob("*.json"):
        if artifact_path.name.startswith(
            "."
        ):  # some hidden file (probably created by OS, especially the Mac OS)
            continue
        with artifact_path.open() as f:
            artifact = json.load(f)
            artifact["sourcePath"] = str(
                Path(tmp_path).joinpath("contracts", Path(artifact["sourcePath"]).name)
            )
        with artifact_path.open("w") as f:
            json.dump(artifact, f)

    os.chdir(tmp_path)
    yield {
        "ide": "truffle",
        "build_directory": "build/contracts",
        "sources_directory": "contracts",
        "targets": [
            "contracts/Foo.sol",
            "contracts/Bar.sol",
            "contracts/ABC.sol",
            "contracts/Migrations.sol",
        ],
        "deployed_contract_address": "0x1672fB2eb51789aBd1a9f2FE83d69C6f4C883065",
        "additional_addresses": [
            "0x6a432C13a2E980a78F941c136ec804e7CB67E0D9",
            "0x6Bcb21De38753e485f7678C7Ada2a63F688b8579",
            "0x07D9Fb5736CD151C8561798dFBdA5dBCf54cB9E6",
        ],
    }


@pytest.fixture()
def bootstrapped_hardhat_fuzzing_lessons_project(tmp_path):
    with tarfile.open(
        Path(__file__).parent.joinpath(
            "testdata", "hardhat_fuzzing_lessons_project", "artifacts.tar.gz"
        )
    ) as f:
        f.extractall(tmp_path)
    os.chdir(tmp_path)


@pytest.fixture()
def bootstrapped_hardhat_project(tmp_path):
    with tarfile.open(
        Path(__file__).parent.joinpath(
            "testdata", "hardhat_project", "artifacts.tar.gz"
        )
    ) as f:
        f.extractall(tmp_path)
    os.chdir(tmp_path)
    yield {
        "ide": "hardhat",
        "build_directory": "artifacts",
        "sources_directory": "contracts",
        "targets": [
            "contracts/Foo.sol",
            "contracts/Bar.sol",
            "contracts/ABC.sol",
            "contracts/Migrations.sol",
        ],
        "deployed_contract_address": "0x81c5D21c4a70ADE85b39689DF5a14B5b5027C28e",
        "additional_addresses": [
            "0x89cf0b64A1612d8AB6320FE8aCfb99E2A1654Dc5",
            "0x128B125f3D14338E71AA0C213B3FfC3D545C8c47",
            "0xa5528c75E001Eff845A36577D14a7d3F6F5Ed4C4",
        ],
    }


@pytest.fixture()
def bootstrapped_brownie_project(tmp_path):
    with tarfile.open(
        Path(__file__).parent.joinpath(
            "testdata", "brownie_project", "artifacts.tar.gz"
        )
    ) as f:
        f.extractall(tmp_path)
    os.chdir(tmp_path)
    yield {
        "ide": "brownie",
        "build_directory": "build/contracts",
        "sources_directory": "contracts",
        "targets": [
            "contracts/Foo.sol",
            "contracts/Bar.sol",
            "contracts/ABC.sol",
            "contracts/Migrations.sol",
        ],
        "deployed_contract_address": "0xD94bC01dF83804b671912a866F659E63CC76CfC8",
        "additional_addresses": [
            "0x44C9Fb4D18748B5cc1967fBCF3c1Bd29EDa3B897",
            "0x55DB595E6912454eEE515c44b6D66BC2607DD8e6",
            "0x4d18850465B8a522E98a450Dd951b67f3f159092",
        ],
    }


@pytest.fixture()
def bootstrapped_dapptools_project(tmp_path):
    with tarfile.open(
        Path(__file__).parent.joinpath(
            "testdata", "dapptools_project", "artifacts.tar.gz"
        )
    ) as f:
        f.extractall(tmp_path)
    os.chdir(tmp_path)
    yield {
        "ide": "dapptools",
        "build_directory": "out",
        "sources_directory": "src",
        "targets": ["src/Foo.sol", "src/Bar.sol", "src/ABC.sol", "src/Migrations.sol"],
        "deployed_contract_address": "0xCBB2e00b2EbdAF0296252f3301107052B599B11f",
        "additional_addresses": [
            "0x44F916B4598182465c7C2fDcC559c3d9c6A344fA",
            "0x4D6026D3457843C1f653fC29A8c1033Af6F7D25b",
            "0xA2817092A47fc56E5C88409322E11d5A853B1D31",
        ],
    }


@pytest.fixture()
def scribble_project(tmp_path):
    with tarfile.open(
        Path(__file__).parent.joinpath(
            "testdata", "scribble_project", "artifacts.tar.gz"
        )
    ) as f:
        f.extractall(tmp_path)
    os.chdir(tmp_path)
    yield {
        "ide": "truffle",
        "build_directory": "build/contracts",
        "sources_directory": "contracts",
        "targets": ["contracts/VulnerableToken.sol"],
        "deployed_contract_address": "0x1672fB2eb51789aBd1a9f2FE83d69C6f4C883065",
        "additional_addresses": [
            "0x6a432C13a2E980a78F941c136ec804e7CB67E0D9",
            "0x6Bcb21De38753e485f7678C7Ada2a63F688b8579",
            "0x07D9Fb5736CD151C8561798dFBdA5dBCf54cB9E6",
        ],
    }


@pytest.fixture(autouse=True)
def teardown():
    yield
    try:
        remove(".fuzz.yml")
    except:
        pass
