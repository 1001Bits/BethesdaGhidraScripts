"""A rename that did not happen must never be reported as one.

Ghidra refuses ``setName`` when a symbol of that name already sits at the
address -- which is common here, because the CommonLib import pass puts a label
there first.  The old code swallowed the exception and still counted the slot as
``reconciled``, so the summary claimed the binary had been corrected while the
function kept its stale primary name.
"""
import pytest

from vtable_name_reconciler import _promote_existing_symbol, _rename_slot


class _SourceType:
    IMPORTED = 'IMPORTED'


class _Addr:
    def __init__(self, offset):
        self._offset = offset

    def getOffset(self):
        return self._offset


class _Symbol:
    def __init__(self, name, full=None, primary=False):
        self._name = name
        self._full = full or name
        self._primary = primary
        self.promoted = False

    def getName(self, full=False):
        return self._full if full else self._name

    def isPrimary(self):
        return self._primary

    def setPrimary(self):
        self._primary = True
        self.promoted = True


class _CodeUnit:
    def __init__(self):
        self.comment = ''

    def getComment(self, _kind):
        return self.comment

    def setComment(self, _kind, text):
        self.comment = text


class _Program:
    def __init__(self, symbols=()):
        self._symbols = list(symbols)
        self.code_unit = _CodeUnit()

    def getSymbolTable(self):
        program = self

        class _Table:
            def getSymbols(self, _addr):
                return program._symbols
        return _Table()

    def getListing(self):
        program = self

        class _Listing:
            def getCodeUnitAt(self, _addr):
                return program.code_unit
        return _Listing()


class _Namespace:
    def __init__(self, is_global):
        self._global = is_global

    def isGlobal(self):
        return self._global


class _Function:
    def __init__(self, name, in_class_ns=False, raises=None):
        self._name = name
        self._ns = _Namespace(not in_class_ns)
        self._raises = raises
        self.renamed_to = None

    def getParentNamespace(self):
        return self._ns

    def setName(self, name, _source):
        if self._raises is not None:
            raise self._raises
        self._name = name
        self.renamed_to = name


def _rename(func, program):
    return _rename_slot(func, _Addr(0x140CBC8C0), program,
                        'BSResourceNiBinaryStream::seek', 'seek',
                        'BSResourceNiBinaryStream::Func5', False,
                        'BSResourceNiBinaryStream', _SourceType)


def test_plain_rename_succeeds_and_is_reported_as_such():
    func = _Function('Func5')
    program = _Program()
    assert _rename(func, program) is True
    assert func.renamed_to == 'BSResourceNiBinaryStream::seek'
    assert 'Reconciled from stale name' in program.code_unit.comment


def test_duplicate_name_promotes_the_existing_symbol_instead_of_giving_up():
    """The wanted name is already there as a label -- promoting it IS the rename."""
    existing = _Symbol('seek', 'BSResourceNiBinaryStream::seek', primary=False)
    func = _Function('Func5', raises=RuntimeError('DuplicateNameException'))
    program = _Program([_Symbol('Func5', primary=True), existing])

    assert _rename(func, program) is True
    assert existing.promoted, 'the correctly-named symbol must become primary'


def test_rename_failure_is_reported_as_failure_not_success():
    """No symbol of that name at the address: nothing was fixed -- say so."""
    func = _Function('Func5', raises=RuntimeError('DuplicateNameException'))
    program = _Program([_Symbol('SomethingElse', primary=True)])

    assert _rename(func, program) is False


def test_dry_run_changes_nothing_but_still_reports_the_rename():
    func = _Function('Func5')
    program = _Program()
    assert _rename_slot(func, _Addr(0x1000), program, 'C::m', 'm', 'C::Func1',
                        True, 'C', _SourceType) is True
    assert func.renamed_to is None


@pytest.mark.parametrize('primary', [True, False])
def test_promote_matches_on_leaf_or_qualified_name(primary):
    symbol = _Symbol('seek', 'BSResourceNiBinaryStream::seek', primary=primary)
    program = _Program([symbol])

    assert _promote_existing_symbol(program, _Addr(0x1), 'seek') is True
    assert _promote_existing_symbol(
        program, _Addr(0x1), 'BSResourceNiBinaryStream::seek') is True
    assert _promote_existing_symbol(program, _Addr(0x1), 'other') is False
