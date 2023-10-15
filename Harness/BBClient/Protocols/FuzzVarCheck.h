#ifndef _FUZZVARCHECK_H_
#define _FUZZVARCHECK_H_

#include "../BBClientUtilities.h"
#include "Variable.h"
#include "VariableNonVolatile.h"
#include "VariableParsing.h"
#include "VariableRuntimeCache.h"

#define REGISTER_SET_VARIABLE_CHECK_HANDLER 0
#define VARIABLE_PROPERTY_SET 1
#define VARIABLE_PROPERTY_GET 2


//
// To prevent name collisions with possible future globally defined variables,
// other internal firmware data variables that are not defined here must be
// saved with a unique VendorGuid other than EFI_GLOBAL_VARIABLE or
// any other GUID defined by the UEFI Specification. Implementations must
// only permit the creation of variables with a UEFI Specification-defined
// VendorGuid when these variables are documented in the UEFI Specification.
//
UEFI_DEFINED_VARIABLE_ENTRY  mGlobalVariableList[] = {
  {
    EFI_LANG_CODES_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_BS_RT,
      1,
      MAX_UINTN
    },
    InternalVarCheckAsciiString
  },
  {
    EFI_LANG_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT,
      1,
      MAX_UINTN
    },
    InternalVarCheckAsciiString
  },
  {
    EFI_TIME_OUT_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT,
      sizeof (UINT16),
      sizeof (UINT16)
    },
    NULL
  },
  {
    EFI_PLATFORM_LANG_CODES_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_BS_RT,
      1,
      MAX_UINTN
    },
    InternalVarCheckAsciiString
  },
  {
    EFI_PLATFORM_LANG_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT,
      1,
      MAX_UINTN
    },
    InternalVarCheckAsciiString
  },
  {
    EFI_CON_IN_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT,
      sizeof (EFI_DEVICE_PATH_PROTOCOL),
      MAX_UINTN
    },
    InternalVarCheckDevicePath
  },
  {
    EFI_CON_OUT_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT,
      sizeof (EFI_DEVICE_PATH_PROTOCOL),
      MAX_UINTN
    },
    InternalVarCheckDevicePath
  },
  {
    EFI_ERR_OUT_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT,
      sizeof (EFI_DEVICE_PATH_PROTOCOL),
      MAX_UINTN
    },
    InternalVarCheckDevicePath
  },
  {
    EFI_CON_IN_DEV_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_BS_RT,
      sizeof (EFI_DEVICE_PATH_PROTOCOL),
      MAX_UINTN
    },
    InternalVarCheckDevicePath
  },
  {
    EFI_CON_OUT_DEV_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_BS_RT,
      sizeof (EFI_DEVICE_PATH_PROTOCOL),
      MAX_UINTN
    },
    InternalVarCheckDevicePath
  },
  {
    EFI_ERR_OUT_DEV_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_BS_RT,
      sizeof (EFI_DEVICE_PATH_PROTOCOL),
      MAX_UINTN
    },
    InternalVarCheckDevicePath
  },
  {
    EFI_BOOT_ORDER_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT,
      sizeof (UINT16),
      MAX_UINTN
    },
    InternalVarCheckSizeArray
  },
  {
    EFI_BOOT_NEXT_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT,
      sizeof (UINT16),
      sizeof (UINT16)
    },
    NULL
  },
  {
    EFI_BOOT_CURRENT_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_BS_RT,
      sizeof (UINT16),
      sizeof (UINT16)
    },
    NULL
  },
  {
    EFI_BOOT_OPTION_SUPPORT_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_BS_RT,
      sizeof (UINT32),
      sizeof (UINT32)
    },
    NULL
  },
  {
    EFI_DRIVER_ORDER_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT,
      sizeof (UINT16),
      MAX_UINTN
    },
    InternalVarCheckSizeArray
  },
  {
    EFI_SYS_PREP_ORDER_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT,
      sizeof (UINT16),
      MAX_UINTN
    },
    InternalVarCheckSizeArray
  },
  {
    EFI_HW_ERR_REC_SUPPORT_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT,
      sizeof (UINT16),
      sizeof (UINT16)
    },
    NULL
  },
  {
    EFI_SETUP_MODE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      VAR_CHECK_VARIABLE_PROPERTY_READ_ONLY,
      VARIABLE_ATTRIBUTE_BS_RT,
      sizeof (UINT8),
      sizeof (UINT8)
    },
    NULL
  },
  {
    EFI_KEY_EXCHANGE_KEY_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT_AT,
      1,
      MAX_UINTN
    },
    NULL
  },
  {
    EFI_PLATFORM_KEY_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT_AT,
      1,
      MAX_UINTN
    },
    NULL
  },
  {
    EFI_SIGNATURE_SUPPORT_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      VAR_CHECK_VARIABLE_PROPERTY_READ_ONLY,
      VARIABLE_ATTRIBUTE_BS_RT,
      sizeof (EFI_GUID),
      MAX_UINTN
    },
    InternalVarCheckSizeArray
  },
  {
    EFI_SECURE_BOOT_MODE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      VAR_CHECK_VARIABLE_PROPERTY_READ_ONLY,
      VARIABLE_ATTRIBUTE_BS_RT,
      sizeof (UINT8),
      sizeof (UINT8)
    },
    NULL
  },
  {
    EFI_KEK_DEFAULT_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      VAR_CHECK_VARIABLE_PROPERTY_READ_ONLY,
      VARIABLE_ATTRIBUTE_BS_RT,
      1,
      MAX_UINTN
    },
    NULL
  },
  {
    EFI_PK_DEFAULT_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      VAR_CHECK_VARIABLE_PROPERTY_READ_ONLY,
      VARIABLE_ATTRIBUTE_BS_RT,
      1,
      MAX_UINTN
    },
    NULL
  },
  {
    EFI_DB_DEFAULT_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      VAR_CHECK_VARIABLE_PROPERTY_READ_ONLY,
      VARIABLE_ATTRIBUTE_BS_RT,
      1,
      MAX_UINTN
    },
    NULL
  },
  {
    EFI_DBX_DEFAULT_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      VAR_CHECK_VARIABLE_PROPERTY_READ_ONLY,
      VARIABLE_ATTRIBUTE_BS_RT,
      1,
      MAX_UINTN
    },
    NULL
  },
  {
    EFI_DBT_DEFAULT_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      VAR_CHECK_VARIABLE_PROPERTY_READ_ONLY,
      VARIABLE_ATTRIBUTE_BS_RT,
      1,
      MAX_UINTN
    },
    NULL
  },
  {
    EFI_OS_INDICATIONS_SUPPORT_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_BS_RT,
      sizeof (UINT64),
      sizeof (UINT64)
    },
    NULL
  },
  {
    EFI_OS_INDICATIONS_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT,
      sizeof (UINT64),
      sizeof (UINT64)
    },
    NULL
  },
  {
    EFI_VENDOR_KEYS_VARIABLE_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      VAR_CHECK_VARIABLE_PROPERTY_READ_ONLY,
      VARIABLE_ATTRIBUTE_BS_RT,
      sizeof (UINT8),
      sizeof (UINT8)
    },
    NULL
  },
  {
    L"SYS-FirstTime",
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      VAR_CHECK_VARIABLE_PROPERTY_READ_ONLY,
      VARIABLE_ATTRIBUTE_NV_BS,
      sizeof (UINT32),
      sizeof (UINT32)
    },
    NULL
  },
};

UEFI_DEFINED_VARIABLE_ENTRY  mGlobalVariableList2[] = {
  {
    L"Boot####",
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT,
      sizeof (UINT32) + sizeof (UINT16),
      MAX_UINTN
    },
    InternalVarCheckLoadOption
  },
  {
    L"Driver####",
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT,
      sizeof (UINT32) + sizeof (UINT16),
      MAX_UINTN
    },
    InternalVarCheckLoadOption
  },
  {
    L"SysPrep####",
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT,
      sizeof (UINT32) + sizeof (UINT16),
      MAX_UINTN
    },
    InternalVarCheckLoadOption
  },
  {
    L"Key####",
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT,
      sizeof (EFI_KEY_OPTION),
      sizeof (EFI_KEY_OPTION) + 3 * sizeof (EFI_INPUT_KEY)
    },
    InternalVarCheckKeyOption
  },
  {
    L"PlatformRecovery####",
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_BS_RT,
      sizeof (UINT32) + sizeof (UINT16),
      MAX_UINTN
    },
    InternalVarCheckLoadOption
  },
};

//
// EFI_IMAGE_SECURITY_DATABASE_GUID
//
UEFI_DEFINED_VARIABLE_ENTRY  mImageSecurityVariableList[] = {
  {
    EFI_IMAGE_SECURITY_DATABASE,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT_AT,
      1,
      MAX_UINTN
    },
    NULL
  },
  {
    EFI_IMAGE_SECURITY_DATABASE1,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT_AT,
      1,
      MAX_UINTN
    },
    NULL
  },
  {
    EFI_IMAGE_SECURITY_DATABASE2,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      0,
      VARIABLE_ATTRIBUTE_NV_BS_RT_AT,
      1,
      MAX_UINTN
    },
    NULL
  },
};

//
// EFI_HARDWARE_ERROR_VARIABLE
//
UEFI_DEFINED_VARIABLE_ENTRY  mHwErrRecVariable = {
  L"HwErrRec####",
  {
    VAR_CHECK_VARIABLE_PROPERTY_REVISION,
    0,
    VARIABLE_ATTRIBUTE_NV_BS_RT_HR,
    1,
    MAX_UINTN
  },
  NULL
};


EFI_STATUS
EFIAPI
FuzzVarCheck(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzRegisterSetVariableCheckHandler(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzVariablePropertySet(
    IN INPUT_BUFFER *Input
);

EFI_STATUS
EFIAPI
FuzzVariablePropertyGet(
    IN INPUT_BUFFER *Input
);

#endif