#!/usr/bin/env python3
"""Assert no function in the pipeline reads a name that is not bound anywhere.

A NameError in the harness generator costs a whole campaign. EVAL-1 run 42299962707 got
through port, build, instrumentation, discovery, imaging and the detection benchmark -- 25
minutes of work -- and then died at harness generation with

    File "harness_generator/data_analysis/analyze_smi.py", line 742, in analyze_smi
      load_smi_inventory(smi_file)
    NameError: name 'smi_file' is not defined

because a call added at the end of analyze_smi() used a variable that only exists in
analyze_smi_data(). The checks that went with that change imported the function and called
it directly with arguments of their own, which is exactly the shape that cannot catch this:
the name is resolved at run time and only on the real call path.

Python has no import-time check for it and there is no linter in this repo's image, so this
walks each function with the stdlib symtable: a name that is read inside a function and is
neither local there, nor a parameter, nor bound in any enclosing scope, nor a module global,
nor a builtin, is a NameError waiting for the one input that reaches that line.

Scope is the generator and analysis code the campaign runs. A false positive here is
cheap to silence by binding the name; a false negative costs a campaign.
"""

import builtins
import os
import symtable
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The code a campaign actually executes. Kept explicit rather than globbed so that adding a
# tree of vendored third-party Python does not quietly widen what this asserts.
TARGETS = [
    'firness/harness_generator/main.py',
    'firness/harness_generator/data_analysis/analyze_smi.py',
    'firness/harness_generator/data_analysis/cross_module.py',
    'firness/harness_generator/uefi_harness/smi_harness_template.py',
    'firness/harness_generator/uefi_harness/harnesses_template.py',
    'firness/harness_generator/uefi_harness/main_template.py',
    'firness/harness_generator/common/utils.py',
]

BUILTINS = set(dir(builtins))

FAILURES = []


def check(name, condition, detail=''):
    if condition:
        print(f'  ok    {name}')
    else:
        print(f'  FAIL  {name}' + (f' -- {detail}' if detail else ''))
        FAILURES.append(name)


def bound_in(table):
    """Every name this scope binds: assignments, parameters, imports, def/class names."""
    out = set()
    for sym in table.get_symbols():
        if sym.is_assigned() or sym.is_parameter() or sym.is_imported():
            out.add(sym.get_name())
        # a nested def/class binds its own name in the enclosing scope
        if sym.is_namespace():
            out.add(sym.get_name())
    return out


def walk(table, enclosing, path, problems):
    """Collect names read in `table` that nothing in scope binds."""
    here = bound_in(table)
    visible = enclosing | here

    if table.get_type() == 'function':
        for sym in table.get_symbols():
            name = sym.get_name()
            if not sym.is_referenced():
                continue
            if name in visible or name in BUILTINS:
                continue
            # NOT is_global(): symtable reports any name a function merely READS and
            # never assigns as GLOBAL_IMPLICIT, which is precisely the unbound case this
            # exists to find. Skipping it made the check report nothing at all, including
            # the planted defect. Whether such a name is really a global is decided by
            # `visible` above, which carries the module's own bindings.
            #
            # An explicit `global X; X = ...` does bind X even when nothing at module level
            # assigns it, and a free variable is a closure cell the compiler already
            # resolved -- both are bound by definition.
            if sym.is_declared_global() or sym.is_free():
                continue
            problems.append((path, table.get_name(), table.get_lineno(), name))

    # A class body does not contribute its names to nested functions, which is Python's
    # rule and not an oversight here.
    passed = visible if table.get_type() != 'class' else enclosing
    for child in table.get_children():
        walk(child, passed, path, problems)


def main():
    print('No pipeline function reads a name that is never bound')
    problems = []
    missing = []

    for rel in TARGETS:
        path = os.path.join(ROOT, rel)
        if not os.path.exists(path):
            missing.append(rel)
            continue
        src = open(path, encoding='utf-8').read()
        table = symtable.symtable(src, path, 'exec')
        walk(table, bound_in(table), rel, problems)

    check('every target file is present', not missing, str(missing))
    check('no unbound name is read', not problems,
          '; '.join(f'{p}:{fn}() reads {n!r}' for p, fn, _, n in problems[:6]))

    # The check has to be able to see the real thing. Plant the exact defect from run
    # 42299962707 into a copy and confirm it is reported.
    planted = '''
def outer(path):
    return inner(path)

def inner(p):
    return p

def broken():
    return inner(path_that_is_not_bound)
'''
    table = symtable.symtable(planted, '<planted>', 'exec')
    found = []
    walk(table, bound_in(table), '<planted>', found)
    check('the check detects a planted unbound name',
          any(n == 'path_that_is_not_bound' for _, _, _, n in found), str(found))

    # ... and does not cry wolf over the ordinary ways a name becomes visible.
    clean = '''
import os
GLOBAL = 1

def uses_global():
    return GLOBAL + len(os.sep)

def closure():
    captured = 2
    def inner():
        return captured
    return inner()

def declares_global():
    global GLOBAL
    GLOBAL = 3

class K:
    attr = 1
    def method(self):
        return self.attr + GLOBAL

def comprehension(items):
    return [x for x in items if x]

def handler():
    try:
        pass
    except ValueError as exc:
        return exc
'''
    table = symtable.symtable(clean, '<clean>', 'exec')
    noise = []
    walk(table, bound_in(table), '<clean>', noise)
    check('globals, closures, classes and comprehensions are not flagged',
          not noise, str(noise))

    if problems:
        print()
        print('  every unbound read found:')
        for path, func, line, name in problems:
            print(f'    {path}: {func}() near line {line} reads {name!r}')

    print(f'{len(FAILURES)} failure(s)')
    return 1 if FAILURES else 0


if __name__ == '__main__':
    sys.exit(main())
