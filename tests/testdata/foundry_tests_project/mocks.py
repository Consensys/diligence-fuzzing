from io import BytesIO

import pytest

list_output = """
    [⠒] Compiling...
    No files changed, compilation skipped
    {"test/Counter.t.sol":{"CounterTest":["testIncrement","testSetNumber"]}}"""


list_args = {
    '--match-path "test/Counter*"': list_output,
    '--match-path "test/Counter*" --match-contract "Counter*"': list_output,
    "--match-path test/Counter* --match-contract Counter*": list_output,
    '--match-contract "Counter*"': list_output,
    "--match-path test/*": """[⠔] Compiling...
        No files changed, compilation skipped
        {"test/Counter.t.sol":{"CounterTest":["testIncrement","testSetNumber"]},"test/VulnerableToken.t.sol":{"VulnerableTokenTest":["testTransfer"]}}""",
}


def list_callback(process):
    args = " ".join(process.args[4:])
    process.stdout = BytesIO(list_args[args].encode())
    process.returncode = 0
    return process


@pytest.fixture()
def foundry_config_mock(fp):
    result = """
        [profile.default]
        src = 'src'
        test = 'test'
        script = 'script'
        out = 'out'
        libs = ['lib']
        remappings = [
            'ds-test/=lib/forge-std/lib/ds-test/src/',
            'forge-std/=lib/forge-std/src/',
        ]
        auto_detect_remappings = true

        [fuzz]
        runs = 256
    """
    with fp.context() as proc:
        proc.keep_last_process(True)
        proc.register(["forge", "config"], stdout=result)
        yield proc


@pytest.fixture()
def foundry_test_list_mock(fp):
    result = """[⠔] Compiling...
        No files changed, compilation skipped
        {"test/Counter.t.sol":{"CounterTest":["testIncrement","testSetNumber"]},"test/VulnerableToken.t.sol":{"VulnerableTokenTest":["testTransfer"]}}"""
    with fp.context() as proc:
        proc.keep_last_process(True)
        proc.register(
            ["forge", "test", "--list", "--json", fp.any()], callback=list_callback
        )
        yield proc


@pytest.fixture()
def foundry_build_mock(fp):
    with fp.context() as proc:
        proc.keep_last_process(True)
        proc.register(["forge", "build", fp.any()], stdout="")
        yield proc
