import pytest

from fuzzing_cli.fuzz.ide.generic import IDEArtifacts
from tests.common import TEST_BYTECODES


@pytest.mark.parametrize(
    "bytecode, metadata_hash",
    [
        (TEST_BYTECODES[0]["bytecode"], TEST_BYTECODES[0]["hash"]),
        (TEST_BYTECODES[1]["bytecode"], TEST_BYTECODES[1]["hash"]),
        (TEST_BYTECODES[2]["bytecode"], TEST_BYTECODES[2]["hash"]),
        (TEST_BYTECODES[3]["bytecode"], TEST_BYTECODES[3]["hash"]),
    ],
)
def test_get_metadata_hash(bytecode: str, metadata_hash: str):
    _hash = IDEArtifacts.get_metadata_hash(bytecode)
    assert _hash == metadata_hash
