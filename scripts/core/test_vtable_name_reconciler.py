"""A rename that did not happen must never be reported as one.

Ghidra refuses ``setName`` when a symbol of that name already sits at the
address -- which is common here, because the CommonLib import pass puts a label
there first.  The old code swallowed the exception and still counted the slot as
``reconciled``, so the summary claimed the binary had been corrected while the
function kept its stale primary name.
"""
import pytest

from vtable_name_reconciler import (_promote_existing_symbol, _rename_slot,
                                    is_analyst_name)


class _SourceType:
    IMPORTED = 'IMPORTED'
    USER_DEFINED = 'USER_DEFINED'
    ANALYSIS = 'ANALYSIS'


class _Addr:
    def __init__(self, offset):
        self._offset = offset

    def getOffset(self):
        return self._offset


class _Symbol:
    """``at_function_entry`` models Ghidra: setPrimary() only applies to
    non-function symbols, so a label beside a function symbol stays secondary
    and the call returns False."""

    def __init__(self, name, full=None, primary=False, at_function_entry=False,
                 source='IMPORTED', owner=None):
        self._name = name
        self._full = full or name
        self._primary = primary
        self._at_function_entry = at_function_entry
        self._source = source
        self._owner = owner
        self.promoted = False
        self.deleted = False

    def getName(self, full=False):
        return self._full if full else self._name

    def getSource(self):
        return self._source

    def isPrimary(self):
        return self._primary

    def setPrimary(self):
        if self._at_function_entry:
            return False
        self._primary = True
        self.promoted = True
        return True

    def delete(self):
        self.deleted = True
        if self._owner is not None:
            self._owner._symbols.remove(self)
        return True


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
    def __init__(self, name, in_class_ns=False, raises=None, program=None,
                 source='IMPORTED'):
        self._name = name
        self._ns = _Namespace(not in_class_ns)
        self._raises = raises
        self._program = program
        self._source = source
        self.renamed_to = None

    def getParentNamespace(self):
        return self._ns

    def getName(self, _full=False):
        return self._name

    def getSymbol(self):
        return _Symbol(self._name, primary=True, source=self._source)

    def setName(self, name, _source):
        # Ghidra: DuplicateNameException while a symbol of that name is at
        # the address; fine once that label is gone.
        duplicate = self._program is not None and any(
            symbol.getName() == name or symbol.getName(True) == name
            for symbol in self._program._symbols)
        if self._raises is not None and (self._program is None or duplicate):
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


def test_duplicate_label_at_a_function_entry_is_replaced_not_falsely_promoted():
    """setPrimary() cannot promote a label over a function symbol (it returns
    False).  The old code ignored that and reported the slot reconciled while
    the function kept its stale name."""
    program = _Program()
    existing = _Symbol('BSResourceNiBinaryStream::seek',
                       'BSResourceNiBinaryStream::seek', primary=False,
                       at_function_entry=True, owner=program)
    program._symbols[:] = [_Symbol('Func5', primary=True), existing]
    func = _Function('Func5', raises=RuntimeError('DuplicateNameException'),
                     program=program)

    assert _rename(func, program) is True
    assert existing.deleted and not existing.promoted
    assert func.getName() == 'BSResourceNiBinaryStream::seek'


def test_unpromotable_user_label_is_kept_and_reported_as_failure():
    program = _Program()
    existing = _Symbol('BSResourceNiBinaryStream::seek', primary=False,
                       at_function_entry=True, source='USER_DEFINED',
                       owner=program)
    program._symbols[:] = [_Symbol('Func5', primary=True), existing]
    func = _Function('Func5', raises=RuntimeError('DuplicateNameException'),
                     program=program)

    assert _rename(func, program) is False
    assert not existing.deleted and func.getName() == 'Func5'


def test_user_defined_names_are_analyst_work_unless_placeholders():
    typed = _Function('Actor::MyBetterName', source='USER_DEFINED')
    stale = _Function('Actor::Update', source='IMPORTED')
    placeholder = _Function('Func12', source='USER_DEFINED')
    assert is_analyst_name(typed, 'MyBetterName', _SourceType) is True
    assert is_analyst_name(stale, 'Update', _SourceType) is False
    assert is_analyst_name(placeholder, 'Func12', _SourceType) is False


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
