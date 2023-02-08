import pytest

from fuzzing_cli.fuzz.ide.generic import IDEArtifacts


@pytest.mark.parametrize(
    "bytecode, metadata_hash",
    [
        (  # bzzr0
            "0x608060456fea165627a7a723058209bfcd191ae208d998c6143fb5aecdac995d4c395ef81a338751f04f1ed36c7a50029",
            "9bfcd191ae208d998c6143fb5aecdac995d4c395ef81a338751f04f1ed36c7a5",
        ),
        (  # ipfs
            "0x6080604ea264697066735822122067d3638c35c905f4b739a2f36a87ce99b451f2489918e2ebe44988499e3bd5cd64736f6c63430006070033",
            "122067d3638c35c905f4b739a2f36a87ce99b451f2489918e2ebe44988499e3bd5cd",
        ),
        (  # bzzr1
            "0x6080604ea265627a7a72315820417f7029e78a354a21daf47d64a5cbbab03cb009591c1efd0bd5412b2fa56d0a64736f6c63430005100032",
            "417f7029e78a354a21daf47d64a5cbbab03cb009591c1efd0bd5412b2fa56d0a",
        ),
        (  # no metadata
            "0x608060428201905080821115610a4457610a436109b3565b5b9291505056fea164736f6c6343000811000a",
            None,
        ),
    ],
)
def test_get_metadata_hash(bytecode: str, metadata_hash: str):
    _hash = IDEArtifacts.get_metadata_hash(bytecode)
    assert _hash == metadata_hash
