# pylint: disable=C0115,C0114,C0103
from __future__ import annotations

class Instruction:
    size: int
    address: int
    mnemonic: str
    op_str: str


class Node:
    class Block:
        class Capstone:
            insns: list[Instruction]
        capstone: Capstone
    block: Block | None


NodeView = list[Node]
