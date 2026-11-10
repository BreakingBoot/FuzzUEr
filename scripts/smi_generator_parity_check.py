#!/usr/bin/env python3
"""Assert the SMI generator does not quietly skip a step the protocol generator takes.

firness has two generators -- generate_harness for protocols and generate_smi_harness for
SMI handlers -- and they are separate functions with separate bodies. Every step that only
exists in one of them is a capability the other silently lacks, and the symptom is always
far from the cause:

  * resolve_missing_declarations was only in the protocol generator. An edk2 header is not
    required to be self contained, and an SMI harness includes the GUID header of every
    comm buffer it fills -- exactly the kind that leaves its types to the caller. On
    edk2-stable202608 the harness stopped at "unknown type name VARIABLE_POLICY_ENTRY" and
    the campaign reported "no campaign produced a log.json" after 1144s. The fork's copy of
    that header has neither field, so no eval1 campaign ever showed it.
  * the same shape as the five analyzer outputs that come back null in SMI mode.

So rather than assert one step, diff the call sets and require every difference to be
declared here with a reason. A new divergence then fails a check instead of a campaign.

Run: python3 scripts/smi_generator_parity_check.py
"""
import ast
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MAIN = os.path.join(os.path.dirname(HERE), 'firness', 'harness_generator', 'main.py')

# Calls the protocol generator makes that the SMI one deliberately does not, each with the
# reason. Anything NOT in here has to be called by both.
EXPECTED_DIFFERENCES = {
    'generate_code': 'the SMI path calls generate_smi_code instead -- a handler is '
                     'driven through a comm buffer, not an argument list',
}

FAILED = 0
PASSED = 0


def check(what, ok, detail=''):
    global FAILED, PASSED
    if ok:
        PASSED += 1
        print(f'  [OK]   {what}')
    else:
        FAILED += 1
        print(f'  [FAIL] {what}' + (f'\n         {detail}' if detail else ''))


def called_names(tree, function):
    """Every plain function name called in one top-level function's body."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == function:
            out = set()
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name):
                    out.add(inner.func.id)
            return out
    return None


def call_order(tree, function, name):
    """The line a call appears on inside a function, or None."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == function:
            for inner in ast.walk(node):
                if (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name)
                        and inner.func.id == name):
                    return inner.lineno
    return None


def main():
    if not os.path.isfile(MAIN):
        print(f'  [skip] {MAIN} is not here; the firness submodule is not checked out')
        return 0
    print('the SMI generator takes the steps the protocol generator takes')
    tree = ast.parse(open(MAIN, encoding='utf-8').read())

    protocol = called_names(tree, 'generate_harness')
    smi = called_names(tree, 'generate_smi_harness')
    check('both generators are present', protocol is not None and smi is not None,
          f'generate_harness={protocol is not None} '
          f'generate_smi_harness={smi is not None}')
    if protocol is None or smi is None:
        print(f'\n{PASSED} passed, {FAILED} failed')
        return 1

    # Only the module's own helpers. A builtin or a method is not a pipeline step.
    helpers = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    missing = (protocol & helpers) - smi - set(EXPECTED_DIFFERENCES)
    check('the SMI generator skips no undeclared step',
          not missing,
          f'only the protocol generator calls {sorted(missing)}. Either call them from '
          f'generate_smi_harness too, or add each to EXPECTED_DIFFERENCES with the '
          f'reason it does not apply -- a step missing from one generator is a '
          f'capability the other silently lacks')

    for name, why in sorted(EXPECTED_DIFFERENCES.items()):
        check(f'{name} is still absent on purpose ({why[:40]}...)',
              name not in smi or name in protocol,
              f'{name} is declared as a deliberate difference but is now called by both; '
              f'remove it from EXPECTED_DIFFERENCES so the diff stays meaningful')

    # The one that cost run 42730654576, pinned by name as well as by the diff above: it
    # has to run BEFORE the includes and the INF are written, because both are derived
    # from the list it extends.
    resolver = 'resolve_missing_declarations'
    check(f'the SMI generator calls {resolver}', resolver in smi,
          'an SMI harness includes the GUID header of every comm buffer it fills, and '
          'edk2 leaves those headers\' types to the caller')
    for after in ('generate_includes', 'generate_inf'):
        where = call_order(tree, 'generate_smi_harness', resolver)
        later = call_order(tree, 'generate_smi_harness', after)
        check(f'and before {after}',
              where is not None and later is not None and where < later,
              f'{resolver} is at line {where} and {after} at {later}; both are derived '
              f'from the include list, so resolving afterwards changes nothing that '
              f'reaches the build')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
