import ctor_mine
import globals_harvest


class PC:
    CAST = 1
    COPY = 2
    PTRSUB = 3
    PTRADD = 4
    INT_ADD = 5
    MULTIEQUAL = 6
    LOAD = 7
    INDIRECT = 8


class Space:
    def equals(self, other):
        return self is other

    def getAddress(self, offset):
        return Address(self, offset)


class Address:
    def __init__(self, space, offset):
        self.space = space
        self.offset = offset

    def add(self, delta):
        return Address(self.space, self.offset + delta)

    def getAddressSpace(self):
        return self.space

    def getOffset(self):
        return self.offset

    def isMemoryAddress(self):
        return True

    def __eq__(self, other):
        return (isinstance(other, Address) and self.space is other.space and
                self.offset == other.offset)


class Memory:
    @staticmethod
    def contains(address):
        return 0 <= address.getOffset() < 0x10000


class High:
    def __init__(self, name):
        self.name = name

    def getName(self):
        return self.name


class Definition:
    def __init__(self, opcode, *inputs):
        self.opcode = opcode
        self.inputs = inputs

    def getOpcode(self):
        return self.opcode

    def getInput(self, index):
        return self.inputs[index]

    def getInputs(self):
        return self.inputs

    def getNumInputs(self):
        return len(self.inputs)


class Varnode:
    def __init__(self, *, constant=None, address=None, definition=None,
                 high=None, size=8):
        self.constant = constant
        self.address = address
        self.definition = definition
        self.high = High(high) if high else None
        self.size = size

    def isConstant(self):
        return self.constant is not None

    def isAddress(self):
        return self.address is not None

    def getOffset(self):
        return self.constant

    def getAddress(self):
        return self.address

    def getDef(self):
        return self.definition

    def getHigh(self):
        return self.high

    def getSize(self):
        return self.size


def const(value, size=8):
    return Varnode(constant=value, size=size)


def expr(opcode, *inputs):
    return Varnode(definition=Definition(opcode, *inputs))


def test_global_address_arithmetic_and_phi_consensus():
    space = Space()
    memory = Memory()
    base = const(0x1000)
    ptrsub = expr(PC.PTRSUB, base, const(0x20))
    ptradd = expr(PC.PTRADD, base, const(3), const(8))
    assert globals_harvest._ram_addr(
        ptrsub, memory, space, pc=PC)[0].getOffset() == 0x1020
    assert globals_harvest._ram_addr(
        ptradd, memory, space, pc=PC)[0].getOffset() == 0x1018

    same = expr(PC.MULTIEQUAL, ptrsub, const(0x1020))
    conflict = expr(PC.MULTIEQUAL, ptrsub, const(0x1030))
    assert globals_harvest._ram_addr(
        same, memory, space, pc=PC)[0].getOffset() == 0x1020
    assert globals_harvest._ram_addr(
        conflict, memory, space, pc=PC)[0] is None


def test_global_address_uses_signed_pcode_delta():
    space = Space()
    negative_16 = const((1 << 64) - 0x10)
    value = expr(PC.INT_ADD, const(0x1000), negative_16)
    assert globals_harvest._ram_addr(
        value, Memory(), space, pc=PC)[0].getOffset() == 0xFF0

    # PyGhidra/Jython can expose the same 64-bit constant as a signed Java
    # long.  It must not be sign-extended a second time.
    signed_negative_16 = const(-0x10)
    value = expr(PC.INT_ADD, const(0x1000), signed_negative_16)
    assert globals_harvest._ram_addr(
        value, Memory(), space, pc=PC)[0].getOffset() == 0xFF0

    this_ptr = Varnode(high="this")
    field = expr(PC.PTRSUB, this_ptr, signed_negative_16)
    assert ctor_mine._addr_off(field, "this", PC) == -0x10


def test_constructor_parameter_phi_requires_unanimous_identity():
    param_a = Varnode(high="a")
    param_b = Varnode(high="b")
    same = expr(PC.MULTIEQUAL, param_a, param_a)
    conflict = expr(PC.MULTIEQUAL, param_a, param_b)
    params = {"a": "int", "b": "float"}
    assert ctor_mine._val_param(same, params, PC) == "a"
    assert ctor_mine._val_param(conflict, params, PC) is None
