from typing import List, Dict, Set

default_includes = {
    "Library/BaseLib.h",
    "Library/BaseMemoryLib.h",
    "Library/DebugLib.h",
    "Library/MemoryAllocationLib.h",
    "Library/UefiBootServicesTableLib.h",
    "Library/UefiLib.h",
    "Library/UefiRuntimeServicesTableLib.h",
    "Library/UefiApplicationEntryPoint.h",
    "Library/UefiBootManagerLib.h",
    "Library/UefiRuntimeLib.h",
    "Library/PcdLib.h",
    "Library/PrintLib.h",
    "Library/ReportStatusCodeLib.h",
    "Library/TimerLib.h",
    "Library/PciLib.h",
    "Library/SerialPortLib.h",
    "Library/PciExpressLib.h",
    "Library/IoLib.h",
    "Library/SynchronizationLib.h",
    "Uefi/UefiSpec.h"    
}

default_libraries = {
    "UefiApplicationEntryPoint",
    "UefiLib",
    "BaseLib",
    "BaseMemoryLib",
    "DebugLib",
    "UefiBootServicesTableLib",
    "UefiRuntimeServicesTableLib",
    "PcdLib",
    "DxeServicesTableLib",
    "HobLib"
}

type_defs = {
    "INT8": "signed char",
    "BOOLEAN": "unsigned char",
    "UINT8": "unsigned char",
    "CHAR8": "char",
    "INT16": "short",
    "UINT16": "unsigned short",
    "CHAR16": "unsigned short",
    "INT32": "int",
    "UINT32": "unsigned int",
    "INT64": "long long",
    "UINT64": "unsigned long long",
    "INTN": "long",
    "UINTN": "unsigned long"
}

convert_types = {
    "UINT8": "uint8_t",
    "UINT16": "uint16_t",
    "UINT32": "uint32_t",
    "UINT64": "uint64_t",
    "INT8": "int8_t",
    "INT16": "int16_t",
    "INT32": "int32_t",
    "INT64": "int64_t",
    "BOOLEAN": "bool",
    "CHAR8": "char",
    "CHAR16": "char16_t",
    "VOID": "void",
    "VOID*": "void*",
    "UINTN": "uint64_t",
    "INTN": "int64_t",
    "EFI_GUID": "EFI_GUID",
}

scalable_params = [
    "int",
    "char",
    "bool",
    "uint",
    "long",
    "short",
    "float",
    "double",
    "size_t",
    "ssize_t"
]
services_map = {
    "BS": "BootServices",
    "RT": "RuntimeServices",
    "protocol": "Protocols",
    "DS": "DxeServices",
    "other": "OtherFunctions"
}

known_contant_variables = [
    "__CONSTANT_STRING__",
    "__CONSTANT_INT__",
    "__FUNCTION_PTR__",
    "__ENUM_ARG__"
]

ignore_constant_keywords = [
    "max",
    "size",
    "length",
    "min"
]

class Argument:
    def __init__(self, arg_dir: str, arg_type: str, assignment: str, data_type: str, usage: str, variable: str, potential_outputs: List[str] = []):
        self.arg_dir = arg_dir
        self.arg_type = arg_type.replace('const ', '')
        self.assignment = assignment
        self.data_type = data_type.replace('const ', '')
        self.pointer_count = arg_type.count('*')
        self.usage = usage
        self.potential_outputs = potential_outputs
        self.variable = variable

    def to_dict(self):
        return {
            'Arg Dir': self.arg_dir,
            'Arg Type': self.arg_type,
            'Assignment': self.assignment,
            'Data Type': self.data_type,
            'Usage': self.usage,
            'Pointer Count': self.pointer_count,
            'Potential Values': self.potential_outputs,
            'Variable': self.variable
        }

class EnumDef:
    def __init__(self, name: str = "", values: List[str] = [], file: str = ""):
        self.name = name
        self.values = values
        self.file = file

class Function:
    def __init__(self, function: str, arguments: List[Argument], return_type: str = "", service: str = "", includes: Set[str] = [], file: str = ""):
        self.function = function
        self.return_type = return_type
        self.arguments = arguments
        self.file = file
        if service is None:
            service = ""
        self.service = service
        self.includes = includes

class FunctionBlock:
    def __init__(self, arguments: Dict[str, List[Argument]], function: str, service: str = "", includes: Set[str] = [], return_type: str = ""):
        self.arguments = arguments
        if service is None:
            service = ""
        self.service = service
        self.function = function
        self.includes = includes
        self.return_type = return_type

    def to_dict(self):
        return {
            'arguments': {key: [arg.to_dict() for arg in args] for key, args in self.arguments.items()},
            'service': self.service,
            'function': self.function,
            'includes': self.includes,
            'return_type': self.return_type
        }

class Macros:
    def __init__(self, File: str, Name: str, Value: str):
        self.file = File
        self.name = Name
        self.value = Value


class FieldInfo:
    def __init__(self, name: str, type: str):
        self.name = name
        self.type = type

class TypeInfo:
    def __init__(self, name: str = "", fields: List[FieldInfo] = [], file: str = ""):
        self.name = name
        self.fields = fields
        self.file = file

class TypeTracker:
    def __init__(self, arg_type: str, variable: str, pointer_count: int, fuzzable: bool = False):
        self.arg_type = arg_type
        self.name = variable
        self.pointer_count = pointer_count
        self.fuzzable = fuzzable
        