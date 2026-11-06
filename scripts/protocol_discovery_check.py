#!/usr/bin/env python3
"""Assert a protocol is discovered even when its header breaks edk2 convention.

The header scan needs three things to line up before it will call something a protocol:
the struct sits under an Include/Protocol directory, the header declares
`extern EFI_GUID g<Name>ProtocolGuid;`, and the struct's name matches that GUID's name.
Upstream edk2 holds to all three, so the scan looks complete when measured against
upstream. A driver written for one platform often holds to none of them, and then a
protocol that IS installed in the firmware has no target file at all -- the run reports
nothing found there rather than that nothing was looked for.

The install call site has none of those dependencies: it names the GUID and the interface
variable together, and the variable's declaration names the type. This checks that pass
still works, and that it does not start inventing protocols out of unrelated calls.
"""

import os
import sys
import tempfile
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import gen_protocol_inputs as gpi  # noqa: E402

FAILURES = []


def check(name, condition, detail=''):
    if condition:
        print(f'  ok    {name}')
    else:
        print(f'  FAIL  {name}' + (f' -- {detail}' if detail else ''))
        FAILURES.append(name)


HEADER = textwrap.dedent('''
    #ifndef _VENDOR_THING_H_
    #define _VENDOR_THING_H_
    typedef struct _VENDOR_THING_PROTOCOL VENDOR_THING_PROTOCOL;
    typedef
    EFI_STATUS
    (EFIAPI *VENDOR_THING_READ) (
      IN UINT32 Address,
      OUT UINT8 *Buffer
      );
    typedef
    EFI_STATUS
    (EFIAPI *VENDOR_THING_WRITE) (
      IN UINT32 Address,
      IN UINT8 *Buffer
      );
    struct _VENDOR_THING_PROTOCOL {
      VENDOR_THING_READ   ThingRead;
      VENDOR_THING_WRITE  ThingWrite;
    };
    #endif
    ''')

SOURCE = textwrap.dedent('''
    #include "VendorThing.h"
    VENDOR_THING_PROTOCOL  mThingProtocol = {
      ThingReadImpl,
      ThingWriteImpl,
    };
    EFI_STATUS EFIAPI Entry (VOID)
    {
      Handle = NULL;
      Status = gBS->InstallMultipleProtocolInterfaces (
                      &Handle,
                      &gVendorSomethingElseProtocolGuid,
                      &mThingProtocol,
                      NULL
                      );
      return Status;
    }
    ''')

# A driver that installs NULL as its interface -- "Install NULL to DXE data base as
# notify" is a real edk2 idiom and three EVAL-1 drivers use it. There is no interface to
# call, so it must not become a target: a campaign against it spends a container, an
# analysis, a harness build and the whole boot budget on a protocol with no methods.
NULL_SOURCE = textwrap.dedent('''
    EFI_STATUS EFIAPI Entry2 (VOID)
    {
      ImageHandle = NULL;
      Status = gBS->InstallProtocolInterface (
                       &ImageHandle,
                       &gVendorNotifyOnlyProtocolGuid,
                       EFI_NATIVE_INTERFACE,
                       NULL
                       );
      return Status;
    }
    ''')


def main():
    print('pairing a GUID with its interface at the install call')
    pairs = gpi.installed_pairs(SOURCE)
    check('InstallMultipleProtocolInterfaces is paired',
          pairs == [('gVendorSomethingElseProtocolGuid', 'mThingProtocol')], pairs)

    check('a NULL interface is not treated as one',
          gpi.installed_pairs(NULL_SOURCE) == [], gpi.installed_pairs(NULL_SOURCE))

    check('the interface variable gives up its type',
          gpi.interface_type(SOURCE, 'mThingProtocol') == 'VENDOR_THING_PROTOCOL',
          gpi.interface_type(SOURCE, 'mThingProtocol'))

    check('a nested call does not break the comma split',
          gpi.split_args('&Handle, &gA, Foo (x, y), NULL')
          == ['&Handle', '&gA', 'Foo (x, y)', 'NULL'])

    print('finding the struct wherever it is declared')
    structs = gpi.structs_in(HEADER)
    check('a function-pointer struct is indexed by name',
          structs.get('VENDORTHINGPROTOCOL') == ['ThingRead', 'ThingWrite'], structs)

    print('end to end, on a tree that follows none of the conventions')
    with tempfile.TemporaryDirectory() as tree:
        drv = os.path.join(tree, 'VendorPkg', 'Thing')
        os.makedirs(drv)
        # deliberately NOT under Include/Protocol, no extern EFI_GUID, and the struct
        # name does not resemble the GUID name -- the three things the header scan needs
        open(os.path.join(drv, 'VendorThing.h'), 'w').write(HEADER)
        open(os.path.join(drv, 'Thing.c'), 'w').write(SOURCE + NULL_SOURCE)

        header_only = gpi.scan_roots([tree])
        check('the header scan alone finds nothing here, as before',
              header_only == {}, header_only)

        found = gpi.scan_installations(tree)
        check('the install pass finds it anyway',
              'gVendorSomethingElseProtocolGuid' in found, sorted(found))
        if 'gVendorSomethingElseProtocolGuid' in found:
            _, members = found['gVendorSomethingElseProtocolGuid']
            check('with both of its methods',
                  members == ['ThingRead', 'ThingWrite'], members)
        check('and still refuses the NULL-interface one',
              'gVendorNotifyOnlyProtocolGuid' not in found, sorted(found))

    print()
    if FAILURES:
        print(f'{len(FAILURES)} check(s) failed: ' + ', '.join(FAILURES))
        return 1
    print('protocol discovery checks passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
