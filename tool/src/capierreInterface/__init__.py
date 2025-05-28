# pylint: disable=C0115,C0114,C0103
from __future__ import annotations

class InstructionSetWrapper:
    def __init__(self, ins):
        self.ins = ins

    def __eq__(self, other):
        return self.ins.address == other.ins.address

    def __hash__(self):
        return hash(self.ins.address)

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
