"""Find the SMI handlers a source tree registers.

The protocol side of the target list can be discovered from headers -- a GUID and a struct
of function pointers is all firness needs. SMI handlers have no such shape: a handler is an
ordinary function that some driver hands to a registration call at run time, so the only
static evidence of one is the call site.

edk2 registers them three ways, and all three name the handler as an argument:

    gSmst->SmiHandlerRegister (Handler, &Guid, &DispatchHandle);
    SwDispatch->Register (SwDispatch, Handler, &Context, &DispatchHandle);
    gMmst->MmiHandlerRegister (Handler, &Guid, &DispatchHandle);

  python3 scripts/discover_smi.py -s <edk2 root> -o eval_source/evalset/Discovered.txt

Registrations reached through a function pointer stored elsewhere are not found; this is a
lower bound, and it says so rather than implying the list is complete.

The second list this writes is the SOFTWARE SMI one, --sw-output. A handler on the software
dispatch protocol is not addressed by a GUID and takes no caller buffer: it is raised by
writing a command byte to the software SMI port, and the only thing that names it is the
SwSmiInputValue its driver asked to be registered for. That value is what the list carries,
because without it the channel has no address to aim at -- see the --sw-output help for why
a value this pass cannot resolve is left out rather than guessed.
"""

import argparse
import os
import re
import sys

# The handler is the first argument to SmiHandlerRegister/MmiHandlerRegister, and the
# second to a dispatch protocol's Register (the first is the protocol itself).
DIRECT = re.compile(
    r'\b(?:SmiHandlerRegister|MmiHandlerRegister)\s*\(\s*&?\s*([A-Za-z_]\w*)')
DISPATCH = re.compile(
    r'->\s*Register\s*\(\s*[A-Za-z_]\w*\s*,\s*&?\s*([A-Za-z_]\w*)')

# things that are never a handler name
NOISE = {'NULL', 'this', 'Handler', 'Function', 'Callback'}


def discover(root):
    found = {}
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ('Build', '.git')]
        for name in files:
            if not name.endswith('.c'):
                continue
            path = os.path.join(base, name)
            try:
                text = open(path, errors='ignore').read()
            except OSError:
                continue
            if 'HandlerRegister' not in text and '->Register' not in text:
                continue
            for pattern in (DIRECT, DISPATCH):
                for handler in pattern.findall(text):
                    if handler in NOISE or handler.isupper():
                        continue
                    # a handler is defined in the tree, not just referenced
                    if re.search(rf'^\s*{re.escape(handler)}\s*\(', text, re.M) or \
                            re.search(rf'\b{re.escape(handler)}\s*\([^;]*\)\s*\{{', text):
                        found.setdefault(handler, os.path.relpath(path, root))
    return found


#
# A software SMI registration, in the one shape every tree writes it in:
#
#     mSwContext.SwSmiInputValue = B2SWSMI;
#     mSwDispatch->Register (mSwDispatch, B2SmiDispatchHandle, &mSwContext, &mSwHandle);
#
# The field is the discriminator, not the name of the protocol variable. SwSmiInputValue
# is declared by EFI_SMM_SW_REGISTER_CONTEXT and EFI_MM_SW_REGISTER_CONTEXT and by nothing
# else, so a context carrying it IS a software dispatch registration however the tree
# spells the dispatcher -- SmmSwDispatch2, mSwDispatch, EFI_MM_SW_DISPATCH_PROTOCOL. The
# normalised-name test the analyzer's C++ uses has to know all three; this does not.
#
SW_REGISTER = re.compile(
    r'->\s*Register\s*\(\s*[A-Za-z_]\w*\s*,\s*&?\s*([A-Za-z_]\w*)\s*,\s*&?\s*([A-Za-z_]\w*)')
SW_VALUE = re.compile(r'\b(\w+)\s*(?:\.|->)\s*SwSmiInputValue\s*=\s*([^;]+);')
# `(UINTN) -1`, `(UINT8)0xB4` -- a cast tells us nothing about the value behind it.
CAST = re.compile(r'^\s*\(\s*(?:CONST\s+)?[A-Za-z_]\w*\s*\**\s*\)\s*')
DEFINE = r'^[ \t]*#[ \t]*define[ \t]+{name}[ \t]+(.+?)[ \t]*(?:/\*|//|$)'

# The dispatcher refuses 0 and anything above MAXIMUM_SWI_VALUE (PchSmiDispatchSmm.h), and
# the handlers themselves treat a command port of 0 as "not a software SMI" and return. A
# value outside this is not a target; it is a misread constant.
SW_VALUE_MIN = 1
SW_VALUE_MAX = 0xFF


def _unwrap(expr):
    """An initialiser with its casts, parentheses and trailing noise taken off."""
    expr = expr.strip()
    while True:
        stripped = CAST.sub('', expr).strip()
        if stripped.startswith('(') and stripped.endswith(')'):
            stripped = stripped[1:-1].strip()
        if stripped == expr:
            return expr
        expr = stripped


def _constant(expr, text, index):
    """The integer an initialiser denotes, or None if this pass cannot say.

    None is the answer for `(UINTN)-1`, which is not a value at all: it asks the dispatcher
    to allocate the next free command byte at registration time. Every software SMI
    registration in edk2 proper is written that way, and the byte it ends up with depends
    on how many drivers registered first. Guessing it would put a command byte in the
    harness that addresses whichever handler happened to register in that slot on that
    boot -- a different handler on the next build -- so it is left out.
    """
    expr = _unwrap(expr)
    try:
        return int(expr, 0)
    except ValueError:
        pass
    if not re.fullmatch(r'[A-Za-z_]\w*', expr):
        return None
    # The driver's own header, then the tree: B2SWSMI is a #define in the .c that uses it,
    # which is the common case, and the fallback index is built once and only if needed.
    seen = set()
    while expr not in seen:
        seen.add(expr)
        found = re.search(DEFINE.format(name=re.escape(expr)), text, re.M)
        value = found.group(1).strip() if found else index.get(expr)
        if value is None:
            return None
        value = _unwrap(value)
        try:
            return int(value, 0)
        except ValueError:
            if not re.fullmatch(r'[A-Za-z_]\w*', value):
                return None
            expr = value
    return None


def define_index(root):
    """Every object-like #define in the tree, for constants a driver does not define itself."""
    index = {}
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ('Build', '.git')]
        for name in files:
            if not (name.endswith('.h') or name.endswith('.c')):
                continue
            try:
                text = open(os.path.join(base, name), errors='ignore').read()
            except OSError:
                continue
            for found in re.finditer(DEFINE.format(name=r'([A-Za-z_]\w*)'), text, re.M):
                index.setdefault(found.group(1), found.group(2).strip())
    return index


def discover_sw_smi(root):
    """Handler -> (command value, source, the spelling the tree uses) for the sw SMI port.

    Every SwSmiInputValue assignment that feeds a Register call, which is the whole of the
    channel's address space: a command byte nothing registered reaches no handler, and the
    dispatcher says so and returns.
    """
    found = {}
    unresolved = {}
    index = None
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ('Build', '.git')]
        for name in files:
            if not name.endswith('.c'):
                continue
            path = os.path.join(base, name)
            try:
                text = open(path, errors='ignore').read()
            except OSError:
                continue
            if 'SwSmiInputValue' not in text or '->Register' not in text:
                continue
            assigned = list(SW_VALUE.finditer(text))
            if not assigned:
                continue
            for call in SW_REGISTER.finditer(text):
                handler, context = call.group(1), call.group(2)
                if handler in NOISE or handler.isupper():
                    continue
                # The assignment that reaches the call is the last one before it on the
                # same context variable. Tcg2Smm registers twice off one SwContext, so
                # taking the first would give both handlers the first value.
                before = [m for m in assigned
                          if m.group(1) == context and m.start() < call.start()]
                if not before:
                    continue
                source = before[-1]
                # The driver's own file first, and the tree only if that fails. B2SWSMI
                # is a #define in the .c that uses it, which is the common case, so the
                # whole-tree index is usually never built at all -- and `(UINTN)-1`
                # resolves to an integer out of range rather than to nothing, so the
                # registrations that have no constant do not pay for it either.
                value = _constant(source.group(2), text, {})
                if value is None:
                    if index is None:
                        index = define_index(root)
                    value = _constant(source.group(2), text, index)
                line = text.count('\n', 0, source.start()) + 1
                where = f'{os.path.relpath(path, root)}:{line}'
                if value is None or not SW_VALUE_MIN <= value <= SW_VALUE_MAX:
                    unresolved.setdefault(
                        handler, (_unwrap(source.group(2)), where))
                    continue
                found.setdefault(handler, (value, where, _unwrap(source.group(2))))
    for handler in found:
        unresolved.pop(handler, None)
    return found, unresolved


def write_sw_smi(root, output):
    """The software SMI request file, and what it says out loud.

    One line per handler: the name, the command byte as the harness will write it, and the
    registration the byte came from. The citation is not decoration -- a command byte is an
    arbitrary-looking number whose only justification is the line of firmware that asked
    for it, and a reader has no other way to tell a discovered value from an invented one.
    """
    found, unresolved = discover_sw_smi(root)
    lines = []
    for handler in sorted(found):
        value, where, spelling = found[handler]
        note = f' ({spelling})' if spelling != f'0x{value:02X}' else ''
        lines.append(f'{handler}  0x{value:02X}  // {where}{note}')
    print(f'{len(found)} software SMI handler(s) with a resolvable command value in {root}')
    if not lines:
        # No file rather than an empty one. The batch takes every .txt in the request
        # directory as a target, so an empty list is a container, a full analysis and a
        # build spent to reach "no software SMI handler in this tree has a command byte",
        # and a stale file from a previous tree is worse than that -- it would aim this
        # tree's campaign at another tree's command bytes.
        if os.path.isfile(output):
            os.remove(output)
            print(f'  removed {output} -- an empty target list is still a campaign')
        for handler in sorted(unresolved):
            spelling, where = unresolved[handler]
            print(f'  not addressable: {handler} registers for {spelling} at {where}')
        return found
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
    with open(output, 'w') as handle:
        handle.write('\n'.join(lines) + '\n')
    for line in lines:
        print(f'  {line}')
    for handler in sorted(unresolved):
        spelling, where = unresolved[handler]
        print(f'  not addressable: {handler} registers for {spelling} at {where} -- the '
              f'dispatcher assigns the command byte at run time, so no static pass can '
              f'name it')
    print(f'  wrote {output}')
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-s', '--src', required=True, help='edk2 source root')
    parser.add_argument('-o', '--output', help='write the handler list here')
    parser.add_argument('--with-source', action='store_true',
                        help='annotate each handler with the file that registers it')
    parser.add_argument('--require', type=int, default=0,
                        help='fail unless at least this many handlers are found; an '
                             'unattended run cannot tell "this tree has none" from "the '
                             'scan matched nothing because the shape changed"')
    parser.add_argument('--sw-output',
                        help='write the software SMI list here: every handler whose '
                             'registration names a SwSmiInputValue this pass can resolve '
                             'to a constant, with that command byte. A registration that '
                             'asks the dispatcher for the next free value -- (UINTN)-1, '
                             'which is how edk2 proper writes every one of them -- is '
                             'counted and left out, because the byte it gets depends on '
                             'registration order at run time and a guess would address '
                             'whichever handler landed in that slot')
    args = parser.parse_args()

    if not os.path.isdir(args.src):
        print(f'no such directory: {args.src}', file=sys.stderr)
        return 2
    if args.sw_output:
        write_sw_smi(args.src, args.sw_output)
    found = discover(args.src)
    print(f'{len(found)} SMI handler(s) registered in {args.src}')
    if not found:
        print('  none found -- this tree may register them through a stored function '
              'pointer, which no static pass of this kind can see')
    lines = []
    for handler in sorted(found):
        lines.append(f'{handler}  // {found[handler]}' if args.with_source else handler)
    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, 'w') as handle:
            handle.write('\n'.join(lines) + '\n')
        print(f'  wrote {args.output}')
    else:
        for line in lines[:20]:
            print(f'  {line}')
    if args.require and len(found) < args.require:
        print(f'  fewer than the {args.require} handler(s) required', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
