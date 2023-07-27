import rlp
from Crypto.Hash import keccak


def mk_contract_address(sender: str, nonce: int, prefix=False) -> str:
    # TODO: maybe add another method to derive contract address?
    """
    A contract address is derived from the sender address and the nonce using keccak256.

    Parameters:
    sender (str): The sender address.
    nonce (int): The nonce of the sender's account.
    prefix (bool): Whether to prefix the address with 0x.

    Returns:
    str: The contract address.
    """

    sender_address = bytes.fromhex(sender)
    address = keccak.new(
        digest_bits=256, data=rlp.encode([sender_address, nonce])
    ).digest()[12:]
    if prefix:
        return f"0x{address.hex().lower()}"
    return address.hex().lower()
