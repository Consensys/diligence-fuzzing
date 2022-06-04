import rlp
from Crypto.Hash import keccak


def mk_contract_address(sender: str, nonce: int, prefix=False) -> str:
    sender_address = bytes.fromhex(sender)
    address = keccak.new(
        digest_bits=256, data=rlp.encode([sender_address, nonce])
    ).digest()[12:]
    if prefix:
        return f"0x{address.hex().lower()}"
    return address.hex().lower()
