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


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-s', '--src', required=True, help='edk2 source root')
    parser.add_argument('-o', '--output', help='write the handler list here')
    parser.add_argument('--with-source', action='store_true',
                        help='annotate each handler with the file that registers it')
    args = parser.parse_args()

    if not os.path.isdir(args.src):
        print(f'no such directory: {args.src}', file=sys.stderr)
        return 2
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
    return 0


if __name__ == '__main__':
    sys.exit(main())
