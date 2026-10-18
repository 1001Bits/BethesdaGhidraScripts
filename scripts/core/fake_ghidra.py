"""A tiny in-memory stand-in for the Ghidra API used by generated importers.

Test support only.  It lets ``test_import_gen_fixes.py`` EXECUTE a complete
importer produced by ``ghidra_import_gen.generate_script`` (types, symbols,
fallback symbols, vtable naming, provenance, transactions) without Ghidra, so
behavioural regressions in the embedded script templates are caught by plain
pytest.  Only what the templates touch is modelled; semantics that matter to
the tests (REPLACE conflict handling, name validation, signature sources,
nested transactions) follow Ghidra's.
"""

import sys
import types


class JavaError(Exception):
    """Stands in for a Java exception surfacing through PyGhidra."""


# ---------------------------------------------------------------- data types
class CategoryPath(object):
    def __init__(self, path):
        self.path = str(path) if str(path).startswith('/') else '/' + str(path)

    def getPathElements(self):
        return [part for part in self.path.split('/') if part]

    def __str__(self):
        return self.path

    def __eq__(self, other):
        return str(self) == str(other)

    def __hash__(self):
        return hash(self.path)


class _JavaClass(object):
    def __init__(self, name):
        self._name = name

    def getSimpleName(self):
        return self._name


class DataType(object):
    LENGTH = 0
    NAME = None

    def __init__(self, category='/', name=None, length=None):
        self._category = category if isinstance(category, CategoryPath) \
            else CategoryPath(category)
        self._name = name if name is not None else (self.NAME or type(self).__name__)
        self._length = self.LENGTH if length is None else length

    def getName(self):
        return self._name

    def getCategoryPath(self):
        return self._category

    def getLength(self):
        return self._length

    def getClass(self):
        return _JavaClass(type(self).__name__)


class DefaultDataType(DataType):
    NAME = 'undefined'
    LENGTH = 1


def _builtin(class_name, display, length):
    return type(class_name, (DataType,), {'NAME': display, 'LENGTH': length})


VoidDataType = _builtin('VoidDataType', 'void', 0)
ByteDataType = _builtin('ByteDataType', 'byte', 1)
WordDataType = _builtin('WordDataType', 'word', 2)
DWordDataType = _builtin('DWordDataType', 'dword', 4)
QWordDataType = _builtin('QWordDataType', 'qword', 8)
CharDataType = _builtin('CharDataType', 'char', 1)
BooleanDataType = _builtin('BooleanDataType', 'bool', 1)
FloatDataType = _builtin('FloatDataType', 'float', 4)
DoubleDataType = _builtin('DoubleDataType', 'double', 8)
ShortDataType = _builtin('ShortDataType', 'short', 2)
IntegerDataType = _builtin('IntegerDataType', 'int', 4)
LongLongDataType = _builtin('LongLongDataType', 'longlong', 8)
UnsignedShortDataType = _builtin('UnsignedShortDataType', 'ushort', 2)
UnsignedIntegerDataType = _builtin('UnsignedIntegerDataType', 'uint', 4)
UnsignedLongLongDataType = _builtin('UnsignedLongLongDataType', 'ulonglong', 8)


class PointerDataType(DataType):
    def __init__(self, target=None, size=8):
        name = (target.getName() + ' *') if target is not None else 'pointer'
        category = target.getCategoryPath() if target is not None else '/'
        DataType.__init__(self, category, name, size)
        self.target = target


class ArrayDataType(DataType):
    def __init__(self, element, count, element_length):
        DataType.__init__(self, '/', '{}[{}]'.format(element.getName(), count),
                          count * element_length)
        self.element = element
        self.count = count


class Enum(DataType):
    """ghidra.program.model.data.Enum (interface)."""


class EnumDataType(Enum):
    def __init__(self, category, name, size):
        DataType.__init__(self, category, name, size)
        self.values = {}

    def add(self, name, value):
        if name in self.values:
            raise JavaError('IllegalArgumentException: ' + name + ' already exists')
        self.values[name] = int(value)

    def getNames(self):
        return list(self.values)

    def getValue(self, name):
        return self.values[name]


class _Component(object):
    def __init__(self, offset, datatype, length, name):
        self.offset, self.datatype, self.length, self.name = (
            offset, datatype, length, name)

    def getOffset(self):
        return self.offset

    def getLength(self):
        return self.length

    def getFieldName(self):
        return self.name

    def getDataType(self):
        return self.datatype


class Composite(DataType):
    def __init__(self, category, name, size=0):
        DataType.__init__(self, category, name, size)
        self.components = []

    def getDefinedComponents(self):
        return sorted(self.components, key=lambda c: c.offset)

    def field(self, name):
        return next(c for c in self.components if c.name == name)


class StructureDataType(Composite):
    def replaceAtOffset(self, offset, datatype, length, name, comment):
        if offset < 0 or offset + length > self._length:
            raise JavaError('IllegalArgumentException: outside structure')
        self.components = [c for c in self.components
                           if c.offset + c.length <= offset
                           or c.offset >= offset + length]
        self.components.append(_Component(offset, datatype, length, name))

    def insertBitFieldAt(self, *_args):
        pass


class Union(Composite):
    """ghidra.program.model.data.Union (interface)."""


class UnionDataType(Union):
    def add(self, datatype, length, name, comment):
        self.components.append(_Component(0, datatype, length, name))
        self._length = max(self._length, length)

    def addBitField(self, *_args):
        pass


class ParameterDefinitionImpl(object):
    def __init__(self, name, datatype, comment):
        self.name, self.datatype = name, datatype

    def getName(self):
        return self.name

    def getDataType(self):
        return self.datatype


class FunctionDefinitionDataType(DataType):
    def __init__(self, category, name, dtm=None):
        DataType.__init__(self, category, name, -1)
        self.return_type = DefaultDataType()
        self.arguments = []
        self.calling_convention = None

    def setReturnType(self, datatype):
        self.return_type = datatype

    def getReturnType(self):
        return self.return_type

    def setArguments(self, arguments):
        self.arguments = list(arguments)

    def getArguments(self):
        return self.arguments

    def setCallingConvention(self, name):
        self.calling_convention = name

    def param_names(self):
        return [a.getName() for a in self.arguments]


class DataTypeConflictHandler(object):
    REPLACE_HANDLER = 'REPLACE'


class ArrayList(list):
    def add(self, item):
        self.append(item)


class DataTypeManager(object):
    def __init__(self):
        self.types = {}          # (category, name) -> DataType
        self.transactions = []

    def addDataType(self, datatype, handler):
        self.types[(str(datatype.getCategoryPath()), datatype.getName())] = datatype
        return datatype

    def seed(self, datatype):
        """A type that existed BEFORE this importer run."""
        return self.addDataType(datatype, None)

    def findDataTypes(self, name, results):
        for (_category, leaf), datatype in sorted(self.types.items()):
            if leaf == name:
                results.add(datatype)

    def getDataType(self, category, name):
        return self.types.get((str(category), name))

    def getPointer(self, datatype, size):
        return PointerDataType(datatype, size)

    def startTransaction(self, label):
        self.transactions.append(('start', label))
        return len(self.transactions)

    def endTransaction(self, tx, commit):
        self.transactions.append(('end', tx, commit))
        return True


# -------------------------------------------------------------------- program
class SourceType(object):
    DEFAULT = 'DEFAULT'
    ANALYSIS = 'ANALYSIS'
    IMPORTED = 'IMPORTED'
    USER_DEFINED = 'USER_DEFINED'


class SymbolType(object):
    LABEL = 'LABEL'
    FUNCTION = 'FUNCTION'


class _GlobalNamespace(object):
    def equals(self, other):
        return other is self


GLOBAL_NAMESPACE = _GlobalNamespace()


class Address(object):
    def __init__(self, offset):
        self.offset = int(offset)

    def add(self, amount):
        return Address(self.offset + int(amount))

    def getOffset(self):
        return self.offset

    def __eq__(self, other):
        return isinstance(other, Address) and other.offset == self.offset

    def __hash__(self):
        return hash(self.offset)

    def __repr__(self):
        return 'Address(0x{:X})'.format(self.offset)


def _check_symbol_name(name):
    if not name or any(ch.isspace() for ch in name):
        raise JavaError('InvalidInputException: invalid symbol name: ' + repr(name))


class _Block(object):
    def __init__(self, name, start, size, execute):
        self.name, self.start, self.size, self.execute = name, start, size, execute

    def getName(self):
        return self.name

    def isInitialized(self):
        return True

    def isExecute(self):
        return self.execute

    def getEnd(self):
        return Address(self.start + self.size - 1)


class _Memory(object):
    def __init__(self, program):
        self.program = program
        self.qwords = {}

    def getBlock(self, address):
        for block in self.program.blocks:
            if block.start <= address.getOffset() < block.start + block.size:
                return block
        return None

    def getByte(self, address):
        return 0x90 - 256

    def getLong(self, address):
        if address.getOffset() not in self.qwords:
            raise JavaError('MemoryAccessException')
        return self.qwords[address.getOffset()]


class _Signature(object):
    def __init__(self, function):
        self.function = function

    def getReturnType(self):
        fdef = self.function.fdef
        return fdef.getReturnType() if fdef is not None else DefaultDataType()


class Function(object):
    def __init__(self, program, address, name):
        self.program, self.address, self.name = program, address, name
        self.name_source = SourceType.DEFAULT
        self.fdef = None
        self.signature_source = SourceType.DEFAULT

    def getName(self):
        return self.name

    def setName(self, name, source):
        _check_symbol_name(name)
        if name.startswith(self.program.fail_name_prefix):
            raise JavaError('DuplicateNameException: ' + name)
        # Ghidra: a label of that name at the same address and namespace
        # blocks the rename.
        if any(s.name == name and s.address == self.address for s in self.program.labels):
            raise JavaError('DuplicateNameException: A symbol named ' + name +
                            ' already exists at this address!')
        self.name, self.name_source = name, source

    def getEntryPoint(self):
        return self.address

    def getParentNamespace(self):
        return GLOBAL_NAMESPACE

    def isExternal(self):
        return False

    def getSignature(self):
        return _Signature(self)

    def getSignatureSource(self):
        return self.signature_source

    def setCallingConvention(self, name):
        pass


class _FunctionManager(object):
    def __init__(self, program):
        self.program = program

    def getFunctionAt(self, address):
        return self.program.functions.get(address.getOffset())

    def getFunctionContaining(self, address):
        return self.getFunctionAt(address)

    def getFunctions(self, forward):
        return [self.program.functions[key] for key in sorted(self.program.functions)]


class _Symbol(object):
    def __init__(self, name, address, program=None, source=SourceType.IMPORTED):
        self.name, self.address = name, address
        self.program, self.source = program, source

    def getName(self):
        return self.name

    def getAddress(self):
        return self.address

    def getSymbolType(self):
        return SymbolType.LABEL

    def getParentNamespace(self):
        return GLOBAL_NAMESPACE

    def getSource(self):
        return self.source

    def delete(self):
        self.program.labels.remove(self)
        return True


class _SymbolTable(object):
    def __init__(self, program):
        self.program = program

    def createLabel(self, address, name, source):
        _check_symbol_name(name)
        if name.startswith(self.program.fail_name_prefix):
            raise JavaError('InvalidInputException: refused ' + name)
        for existing in self.program.labels:
            if existing.name == name and existing.address == address:
                return existing          # Ghidra returns the existing symbol
        symbol = _Symbol(name, address, self.program, source)
        self.program.labels.append(symbol)
        return symbol

    def getSymbols(self, name_or_address):
        if isinstance(name_or_address, Address):
            return [s for s in self.program.labels if s.address == name_or_address]
        return [s for s in self.program.labels if s.name == name_or_address]

    def getAllSymbols(self, include_dynamic):
        return list(self.program.labels)

    def getPrimarySymbol(self, address):
        return next((s for s in self.program.labels if s.address == address), None)


class _CodeUnit(object):
    def __init__(self, program, address):
        self.program, self.address = program, address

    def getComment(self, kind):
        return self.program.comments.get(self.address.getOffset())

    def setComment(self, kind, text):
        self.program.comments[self.address.getOffset()] = text


class _Listing(object):
    def __init__(self, program):
        self.program = program

    def getCodeUnitAt(self, address):
        return _CodeUnit(self.program, address)

    getCodeUnitContaining = getCodeUnitAt


class _Options(object):
    def __init__(self):
        self.strings = {}

    def getString(self, key, default):
        return self.strings.get(key, default)

    def setString(self, key, value):
        self.strings[key] = value

    def getLong(self, key, default):
        return default


class Program(object):
    PROGRAM_INFO = 'Program Information'

    def __init__(self, manifest):
        self.manifest = manifest
        self.image_base = int(manifest['image_base'])
        self.dtm = DataTypeManager()
        self.blocks = [
            _Block(section['name'], self.image_base + int(section['rva']),
                   max(int(section.get('virtual_size', 0)),
                       int(section.get('raw_size', 0))),
                   bool(section.get('executable')))
            for section in manifest['sections']]
        self.functions = {}
        self.labels = []
        self.comments = {}
        self.options = _Options()
        self.memory = _Memory(self)
        self.transactions = []       # ('start', label) / ('end', label, commit)
        self._open = []
        self.fail_name_prefix = '\0never'
        self.fail_signature_at = set()
        self.fail_provenance = False

    # -- fixtures
    def add_function(self, rva, name=None):
        address = Address(self.image_base + rva)
        function = Function(self, address, name or 'FUN_{:08x}'.format(address.offset))
        self.functions[address.offset] = function
        return function

    def function_at(self, rva):
        return self.functions[self.image_base + rva]

    def comment_at(self, rva):
        return self.comments.get(self.image_base + rva) or ''

    def committed(self, label):
        return [event[2] for event in self.transactions
                if event[0] == 'end' and event[1] == label]

    # -- Ghidra API
    def getDataTypeManager(self):
        return self.dtm

    def getDefaultPointerSize(self):
        return int(self.manifest['pointer_size'])

    def getImageBase(self):
        return Address(self.image_base)

    def getMemory(self):
        return self.memory

    def getFunctionManager(self):
        return _FunctionManager(self)

    def getSymbolTable(self):
        return _SymbolTable(self)

    def getListing(self):
        return _Listing(self)

    def getOptions(self, name):
        return self.options

    def getExecutablePath(self):
        return ''

    def getExecutableSHA256(self):
        return self.manifest['sha256']

    def getCurrentTransactionInfo(self):
        return object() if self._open else None

    def startTransaction(self, label):
        if label == 'BGS provenance' and self.fail_provenance:
            raise JavaError('provenance storage failed')
        self.transactions.append(('start', label))
        self._open.append(label)
        return len(self._open)

    def endTransaction(self, tx, commit):
        label = self._open.pop()
        self.transactions.append(('end', label, bool(commit)))
        return not self._open


class ApplyFunctionSignatureCmd(object):
    def __init__(self, address, fdef, source, *_rest):
        self.address, self.fdef, self.source = address, fdef, source

    def applyTo(self, program):
        function = program.functions.get(self.address.getOffset())
        if function is None or self.address.getOffset() in program.fail_signature_at:
            return False
        function.fdef = self.fdef
        function.signature_source = self.source
        return True

    def getStatusMsg(self):
        return 'rejected by fake Ghidra'


class DisassembleCommand(object):
    def __init__(self, *_args):
        pass

    def applyTo(self, program):
        return True


class CParserUtils(object):
    @staticmethod
    def parseSignature(service, program, prototype, handle_errors):
        fdef = FunctionDefinitionDataType('/', prototype.split('(')[0].split()[-1])
        fdef.setReturnType(IntegerDataType())
        inside = prototype[prototype.index('(') + 1:prototype.rindex(')')]
        fdef.setArguments([
            ParameterDefinitionImpl(part.split()[-1], DataType(), '')
            for part in inside.split(',') if part.strip() and part.strip() != 'void'])
        return fdef


class _Monitor(object):
    def setMessage(self, message):
        pass


def _module(name, **attributes):
    module = types.ModuleType(name)
    module.__dict__.update(attributes)
    return module


def install():
    """Register the fake ``ghidra`` / ``java`` packages; return the old ones."""
    data = _module(
        'ghidra.program.model.data',
        **{name: value for name, value in globals().items()
           if name.endswith('DataType') or name in (
               'CategoryPath', 'DataTypeConflictHandler',
               'ParameterDefinitionImpl', 'Enum', 'Composite', 'Union')})
    modules = {
        'ghidra': _module('ghidra'),
        'ghidra.program': _module('ghidra.program'),
        'ghidra.program.model': _module('ghidra.program.model'),
        'ghidra.program.model.symbol': _module(
            'ghidra.program.model.symbol', SourceType=SourceType,
            SymbolType=SymbolType),
        'ghidra.program.model.data': data,
        'ghidra.program.model.listing': _module(
            'ghidra.program.model.listing', Program=Program),
        'ghidra.app': _module('ghidra.app'),
        'ghidra.app.cmd': _module('ghidra.app.cmd'),
        'ghidra.app.cmd.disassemble': _module(
            'ghidra.app.cmd.disassemble', DisassembleCommand=DisassembleCommand),
        'ghidra.app.cmd.function': _module(
            'ghidra.app.cmd.function',
            ApplyFunctionSignatureCmd=ApplyFunctionSignatureCmd),
        'ghidra.app.util': _module('ghidra.app.util'),
        'ghidra.app.util.cparser': _module('ghidra.app.util.cparser'),
        'ghidra.app.util.cparser.C': _module(
            'ghidra.app.util.cparser.C', CParserUtils=CParserUtils),
        'java': _module('java'),
        'java.util': _module('java.util', ArrayList=ArrayList),
        'java.util.ArrayList': ArrayList,
    }
    for name, module in modules.items():
        parent, _, child = name.rpartition('.')
        if parent and isinstance(modules.get(parent), types.ModuleType):
            setattr(modules[parent], child, module)
    previous = {name: sys.modules.get(name) for name in modules}
    sys.modules.update(modules)
    return previous


def uninstall(previous):
    for name, module in previous.items():
        if module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module


def run_importer(source, program, path='<generated-importer>'):
    """Execute a generated importer against *program*; return its globals."""
    created = []

    def create_function(address, name):
        function = Function(program, address,
                            'FUN_{:08x}'.format(address.getOffset()))
        program.functions[address.getOffset()] = function
        created.append(function)
        return function

    namespace = {
        '__name__': '__bgs_generated_importer__',
        'currentProgram': program,
        'monitor': _Monitor(),
        'createFunction': create_function,
    }
    previous = install()
    try:
        exec(compile(source, path, 'exec'), namespace)
    finally:
        uninstall(previous)
    namespace['__created_functions__'] = created
    return namespace
