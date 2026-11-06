#!/usr/bin/env python3
"""Assert the SMI generator covers the handlers it can and explains the ones it cannot.

An SMI handler reached no fuzzing for one of three silent reasons, and every one of them
read from the outside as "this tree's handlers are clean":

  1. its parameter block is declared in a driver-private header, so the generator dropped
     it rather than emit a harness that cannot compile;
  2. the analyser recorded VOID * for the buffer, which carries no fields and whose
     sizeof is 1, so the harness sent a one-byte message and called it the payload;
  3. the analyser never recorded the handler at all, in which case it was not even
     dropped -- it was absent, which is indistinguishable from a tree that has none.

All three are fixed, and the fixes are what this checks. It also checks the message length
can go DOWN, because a handler that fails to bound its comm buffer from below is the most
common SMM defect of all and a harness that can only grow never asks.

Deliberately no container, no edk2 checkout and no analyser run: those belong to
build_sweep.sh. This is the unit-level guard that the logic still does what it says.
"""

import ast
import os
import sys
import tempfile
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
GEN = os.path.join(HERE, '..', 'firness', 'harness_generator')
sys.path.insert(0, GEN)

from common.vendor_types import resolve, render, bare_name, split_array  # noqa: E402

FAILURES = []


def check(name, condition, detail=''):
    if condition:
        print(f'  ok    {name}')
    else:
        print(f'  FAIL  {name}' + (f' -- {detail}' if detail else ''))
        FAILURES.append(name)


class TI:
    def __init__(self, name, fields, file):
        self.name, self.fields, self.file = name, fields, file


class FI:
    def __init__(self, name, type):
        self.name, self.type = name, type


def lift(names):
    """Run the named top-level defs out of analyze_smi.py without importing it.

    analyze_smi.py imports fuzzywuzzy at module scope, which is not installed on a runner
    and has nothing to do with deciding which handlers can be harnessed. This compiles the
    real source of the real functions, so the check still fails when they change.
    """
    path = os.path.join(GEN, 'data_analysis', 'analyze_smi.py')
    tree = ast.parse(open(path, encoding='utf-8').read())
    want = [node for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.Assign))
            and (getattr(node, 'name', None) in names
                 or (isinstance(node, ast.Assign)
                     and any(getattr(t, 'id', None) in names for t in node.targets)))]
    missing = [n for n in names
               if not any(getattr(node, 'name', None) == n
                          or (isinstance(node, ast.Assign)
                              and any(getattr(t, 'id', None) == n for t in node.targets))
                          for node in want)]
    if missing:
        raise SystemExit(f'analyze_smi.py no longer defines: {", ".join(missing)}')
    space = {'os': os, 'print': print, 'Dict': dict, 'List': list,
             'SmiInfo': lambda name, type, guid, file='': TI(name, [], file),
             'TypeInfo': TI}
    exec(compile(ast.Module(body=want, type_ignores=[]), 'analyze_smi.py', 'exec'), space)
    return space


def template_strings(function):
    """Every string literal the named generator function can emit, from its AST.

    Not a grep: a comment mentioning the shrink branch would satisfy a substring search of
    the file, and an earlier check in this project passed for exactly that reason.
    """
    path = os.path.join(GEN, 'uefi_harness', 'smi_harness_template.py')
    tree = ast.parse(open(path, encoding='utf-8').read())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == function:
            out = []
            for inner in ast.walk(node):
                if isinstance(inner, ast.Constant) and isinstance(inner.value, str):
                    out.append(inner.value)
                elif isinstance(inner, ast.JoinedStr):
                    out.append(''.join(v.value for v in inner.values
                                       if isinstance(v, ast.Constant)
                                       and isinstance(v.value, str)))
            return out
    raise SystemExit(f'smi_harness_template.py no longer defines {function}')


def main():
    includable = lambda info: bool(info and info.file and '/Include/' in info.file)

    print('vendoring a private parameter block')
    types = {
        'PRIVATE_BLOCK': TI('PRIVATE_BLOCK', [FI('Function', 'UINTN'),
                                              FI('Status', 'EFI_STATUS'),
                                              FI('Data', 'UINT8[1024]')],
                            '/w/edk2/OvmfPkg/Thing/Private.h'),
        'PUBLIC_BLOCK': TI('PUBLIC_BLOCK', [FI('A', 'UINT32')],
                           '/w/edk2/MdePkg/Include/Guid/Public.h'),
        'HAS_BAD_FIELD': TI('HAS_BAD_FIELD', [FI('Kind', 'SOME_ENUM')],
                            '/w/edk2/OvmfPkg/Thing/Private.h'),
    }
    order, reason = resolve('PRIVATE_BLOCK', types, {}, includable)
    check('a private struct is vendored, not dropped', order == ['PRIVATE_BLOCK'], reason)

    order, reason = resolve('PUBLIC_BLOCK', types, {}, includable)
    check('an includable struct is left to its own header', order == [], reason)

    order, reason = resolve('HAS_BAD_FIELD', types, {}, includable)
    check('a field type the harness cannot get still drops the handler',
          order is None and 'SOME_ENUM' in (reason or ''), repr(reason))

    emitted = '\n'.join(render(['PRIVATE_BLOCK'], types))
    check('an array field keeps its bound', 'UINT8 Data[1024];' in emitted, emitted)
    check('the vendored block is guarded', '__FIRNESS_VENDORED_TYPES__' in emitted)
    check('pointer fields do not gain a stray space',
          'UINT8 *Buf;' in '\n'.join(render(['P'], {'P': TI('P', [FI('Buf', 'UINT8 *')], '')})))
    check('split_array handles a plain type', split_array('UINTN') == ('UINTN', ''))
    check('bare_name strips qualifiers and stars',
          bare_name('CONST EFI_GUID *') == 'EFI_GUID')

    print('reading a handler that types its own comm buffer')
    space = lift(['_DEFN', '_handler_source', '_body_of', 'payload_from_source',
                  'recover_missing_handlers', 'lifecycle_gate', 'load_discovered'])
    with tempfile.TemporaryDirectory() as tree:
        os.makedirs(os.path.join(tree, 'Drv'))
        open(os.path.join(tree, 'Drv', 'A.c'), 'w').write(textwrap.dedent('''
            BOOLEAN mClosed;
            EFI_STATUS EFIAPI GuidHandler (
              IN EFI_HANDLE DispatchHandle, IN CONST VOID *Context,
              IN OUT VOID *CommBuffer, IN OUT UINTN *CommBufferSize)
            {
              REAL_BLOCK *Typed = (REAL_BLOCK *)CommBuffer;
              if (mClosed) { return EFI_SUCCESS; }
              return EFI_SUCCESS;
            }
            EFI_STATUS EFIAPI Setup (VOID)
            {
              gMmst->MmiHandlerRegister (GuidHandler, &gMyCommGuid, &H);
              return EFI_SUCCESS;
            }
            VOID EFIAPI Later (VOID) { mClosed = TRUE; }
            '''))
        open(os.path.join(tree, 'Drv', 'B.c'), 'w').write(textwrap.dedent('''
            EFI_STATUS EFIAPI PortHandler (
              IN EFI_HANDLE DispatchHandle, IN CONST VOID *Context,
              IN OUT VOID *CommBuffer, IN OUT UINTN *CommBufferSize)
            { return EFI_SUCCESS; }
            EFI_STATUS EFIAPI Setup2 (VOID)
            { mSw->Register (mSw, PortHandler, &Ctx, &Handle); return EFI_SUCCESS; }
            '''))
        kinds = {'REAL_BLOCK': TI('REAL_BLOCK', [FI('Function', 'UINTN')], '')}

        got = space['payload_from_source']('GuidHandler', tree, kinds)
        check("the handler's own cast names the payload", got == 'REAL_BLOCK', repr(got))

        smi = {}
        stuck = space['recover_missing_handlers'](
            smi, ['GuidHandler', 'PortHandler', 'Nowhere'], kinds, tree)
        check('a GUID-keyed handler the analyser missed is recovered',
              'GuidHandler' in smi, sorted(smi))
        check('a dispatch-protocol handler is explained, not silently absent',
              'dispatch protocol' in stuck.get('PortHandler', ''),
              stuck.get('PortHandler'))
        check('a handler with no definition says so',
              'no definition' in stuck.get('Nowhere', ''), stuck.get('Nowhere'))

        flag, where = space['lifecycle_gate']('GuidHandler', tree)
        check('a lifecycle latch the handler tests is reported',
              flag == 'mClosed', f'{flag} / {where}')
        flag, _ = space['lifecycle_gate']('PortHandler', tree)
        check('a handler with no latch is not flagged', flag is None, flag)

        listing = os.path.join(tree, 'Discovered.txt')
        open(listing, 'w').write('GuidHandler  // Drv/A.c\n\nPortHandler\n')
        check('the discovered list tolerates the --with-source form',
              space['load_discovered'](listing) == ['GuidHandler', 'PortHandler'])

    print('the message length can go down as well as up')
    strings = template_strings('harness_generator')
    joined = '\n'.join(strings)
    check('there is a shrink branch',
          any('MessageLength = (UINTN)MessageLengthDelta' in s for s in strings), '')
    # The shrink arm has to reach the lengths that actually divide behaviour. A uniform
    # draw over 0..sizeof puts almost all its mass above the first field a handler reads,
    # so without the boundary table the arm exists but rarely demonstrates anything.
    check('the shrink arm draws from boundary lengths',
          any('mFirnessShortLengths[' in s for s in strings), '')
    # the table is emitted over more than one line, so join before looking at it
    table = ' '.join(s for s in strings if ',' in s and s.strip()[:1].isdigit())
    values = {v.strip() for v in table.replace(' ', '').split(',') if v.strip().isdigit()}
    check('the boundary table starts at zero and reaches past a field offset',
          {'0', '1', '8', '40'} <= values, sorted(values, key=lambda v: int(v)))
    check('there is still a grow branch',
          any('MessageLength += (UINTN)MessageLengthDelta' in s for s in strings), '')
    check('the result is clamped to the comm region',
          'MessageLength > MessageLengthRoom' in joined)
    check('the vendored block reaches the harness through the include header',
          '__FIRNESS_VENDORED_TYPES__' in open(
              os.path.join(GEN, 'common', 'vendor_types.py'), encoding='utf-8').read())

    print()
    if FAILURES:
        print(f'{len(FAILURES)} check(s) failed: ' + ', '.join(FAILURES))
        return 1
    print('SMI coverage checks passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
