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
                  'recover_missing_handlers', 'lifecycle_gate',
                  '_enclosing_function', 'load_discovered'])
    with tempfile.TemporaryDirectory() as tree:
        os.makedirs(os.path.join(tree, 'Drv'))
        open(os.path.join(tree, 'Drv', 'A.c'), 'w').write(textwrap.dedent('''
            /** @file
            Copyright (c) 2010 - 2018, Intel Corporation. All rights reserved.
            **/

            EFI_STATUS
            EFIAPI
            Unrelated (
              VOID
              )
            {
              return EFI_SUCCESS;
            }

            BOOLEAN  mClosed = FALSE;

            EFI_STATUS
            EFIAPI
            GuidHandler (
              IN EFI_HANDLE  DispatchHandle,
              IN CONST VOID  *Context,
              IN OUT VOID    *CommBuffer,
              IN OUT UINTN   *CommBufferSize
              )
            {
              REAL_BLOCK *Typed = (REAL_BLOCK *)CommBuffer;
              Size = AllocateThing (*CommBufferSize);
              CopyMem (Size, CommBuffer, *CommBufferSize);
              if (mClosed) {
                return EFI_SUCCESS;
              }
              return EFI_SUCCESS;
            }

            EFI_STATUS
            EFIAPI
            Setup (
              VOID
              )
            {
              gMmst->MmiHandlerRegister (GuidHandler, &gMyCommGuid, &H);
              gMmst->MmRegisterProtocolNotify (&gEndGuid, Later, &Reg);
              return EFI_SUCCESS;
            }

            VOID
            EFIAPI
            Later (
              VOID
              )
            {
              mClosed = TRUE;
            }
            '''))
        # The other shape: the gate is shut by the same function that registers the
        # handler, so the guarded body is dead for every caller rather than merely late.
        open(os.path.join(tree, 'Drv', 'C.c'), 'w').write(textwrap.dedent('''
            BOOLEAN  mOpen = TRUE;

            EFI_STATUS
            EFIAPI
            DeadHandler (
              IN EFI_HANDLE  DispatchHandle,
              IN CONST VOID  *Context,
              IN OUT VOID    *CommBuffer,
              IN OUT UINTN   *CommBufferSize
              )
            {
              if (mOpen) {
                DoTheInterestingThing (CommBuffer);
              }
              return EFI_SUCCESS;
            }

            EFI_STATUS
            EFIAPI
            DeadEntryPoint (
              VOID
              )
            {
              gSmst->SmiHandlerRegister (DeadHandler, &gDeadGuid, &H);
              mOpen = FALSE;
              return EFI_SUCCESS;
            }
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

        # A doc comment is not a definition. Under re.S the parameter group runs across
        # newlines, so a comment mentioning "Name()" paired its own '(' with a ')' far
        # below it and _handler_source returned the comment as the body. Measured on edk2
        # master: FpdtSmiHandler matched in three files, two of them comments that came
        # first in the walk, and the handler was reported as "no GUID-keyed registration
        # call found" with its registration sitting beside the real definition.
        #
        # In a tree of its own: dropping another handler into `tree` changes what the
        # reachability assertions further down see.
        with tempfile.TemporaryDirectory() as comment_tree:
            os.makedirs(os.path.join(comment_tree, 'Drv'))
            open(os.path.join(comment_tree, 'Drv', 'C.c'), 'w').write(textwrap.dedent("""
                /** @file
                  CommentOnly() will receive untrusted input and do basic validation.

                  Copyright (c) 2026, someone. All rights reserved.
                **/
                EFI_STATUS
                EFIAPI
                SomethingElse (
                  IN UINTN A
                  )
                {
                  return EFI_SUCCESS;
                }
                """))
            where, _ = space['_handler_source']('CommentOnly', comment_tree)
            check('a doc comment is not taken as a definition', where is None,
                  f'{where!r}: the comment names CommentOnly() but nothing defines it, so '
                  f'the walk must keep looking rather than return that file')
            there, _ = space['_handler_source']('SomethingElse', comment_tree)
            check('the real definition in the same file is still found',
                  there is not None,
                  'forbidding the comment must not cost the definition below it')

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

        # Which shape it is decides what to do about it, so the caveat has to say.
        _flag, notify = space['lifecycle_gate']('GuidHandler', tree)
        check('a latch set from a protocol notify names the notify',
              'gEndGuid' in notify and 'Later' in notify, notify)
        check('and says the body is reachable before that event',
              'only before that event' in notify, notify)
        header = ('/** @file\n'
                  'Copyright (c) 2010 - 2018, Intel Corporation. All rights reserved.\n'
                  '**/\n'
                  'EFI_STATUS\n'
                  'EFIAPI\n'
                  'RealFunction (\n'
                  '  VOID\n'
                  '  )\n'
                  '{\n'
                  '  mFlag = TRUE;\n'
                  '}\n')
        check('a file header line is not taken for a function definition',
              space['_enclosing_function'](header, header.index('mFlag')) == 'RealFunction',
              space['_enclosing_function'](header, header.index('mFlag')) or '<none>')
        check('and above every definition the answer is nothing, not a guess',
              space['_enclosing_function'](header, header.index('Copyright')) == '',
              space['_enclosing_function'](header, header.index('Copyright')))
        check("the declaration's own initialiser is not mistaken for it either",
              'Unrelated' not in notify, notify)
        check('calls before the gate are counted as reachable regardless',
              'run before the gate' in notify, notify)

        _flag, dead = space['lifecycle_gate']('DeadHandler', tree)
        check('a latch cleared where the handler is registered is called unreachable',
              'unreachable from every caller' in dead, dead)
        check('and names the function that shuts it',
              'DeadEntryPoint' in dead, dead)
        check('a dead gate reports no reachable prologue',
              'run before the gate' not in dead, dead)

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
