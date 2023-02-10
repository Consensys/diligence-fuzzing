import pytest


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
def foundry_build_mock(fp):
    with fp.context() as proc:
        proc.keep_last_process(True)
        proc.register(["forge", "build", fp.any()], stdout="")
        yield proc
