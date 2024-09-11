/** @file
  The compiler instrumentation routines for AddressSanitizer(ASan).

  Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/


#include <Uefi.h>
#include <Library/Asan.h>
#include <Library/HobLib.h>
#include <Library/UefiRuntimeLib.h>

static const UINT64 kDefaultShadowScale = 3;
#define SHADOW_SCALE kDefaultShadowScale
#define SHADOW_GRANULARITY (1ULL << SHADOW_SCALE)
static BOOLEAN asan_inited = FALSE;
static BOOLEAN asan_is_deactivated = TRUE;
static BOOLEAN AsanCtorFlag = FALSE;
UINT64 mAsanShadowMemoryStart = 0;
UINT64 mAsanShadowMemoryStartPhy = 0;
UINT64 mAsanShadowMemorySize = 0;
UINT64 mAsanShadowMemoryEnd = 0;
UINT64 mPhyMemoryEnd = 0;

VOID
SerialOutput(
  IN  CONST CHAR8      *String
  );

VOID
SerialOutput2(
  IN  CONST CHAR8      *String
  );

VOID
Num2Str8bit(
  IN  UINT8 Number,
  IN  CHAR8* NumStr
  );

VOID
Num2Str16bit(
  IN  UINT16 Number,
  IN  CHAR8* NumStr
  );

VOID
Num2Str64bit(
  IN  UINT64 Number,
  IN  CHAR8* NumStr
  );


void ReportGenericError(UINTN addr, BOOLEAN is_write, UINTN access_size) {

}


// -------------------------- Run-time entry ------------------- {{{1
// exported functions
#define ASAN_REPORT_ERROR(type, is_write, size)                     \
void __asan_report_ ## type ## size(UINTN addr) {                   \
}                                                                   \

ASAN_REPORT_ERROR(load, FALSE, 1)
ASAN_REPORT_ERROR(load, FALSE, 2)
ASAN_REPORT_ERROR(load, FALSE, 4)
ASAN_REPORT_ERROR(load, FALSE, 8)
ASAN_REPORT_ERROR(load, FALSE, 16)
ASAN_REPORT_ERROR(store, TRUE, 1)
ASAN_REPORT_ERROR(store, TRUE, 2)
ASAN_REPORT_ERROR(store, TRUE, 4)
ASAN_REPORT_ERROR(store, TRUE, 8)
ASAN_REPORT_ERROR(store, TRUE, 16)

#define ASAN_REPORT_ERROR_N(type, is_write)                                 \
void __asan_report_ ## type ## _n(UINTN addr, UINTN size) {                 \
}

ASAN_REPORT_ERROR_N(load, FALSE)
ASAN_REPORT_ERROR_N(store, TRUE)



#define DEFINE_ASAN_REPORT_LOAD_NOABORT(size)             \
void __asan_report_load##size##_noabort(UINTN addr)       \
{                                                         \
}                                                         \


#define DEFINE_ASAN_REPORT_STORE_NOABORT(size)                     \
void __asan_report_store##size##_noabort(UINTN addr) \
{                                                          \
}                                                          \


DEFINE_ASAN_REPORT_LOAD_NOABORT(1);
DEFINE_ASAN_REPORT_LOAD_NOABORT(2);
DEFINE_ASAN_REPORT_LOAD_NOABORT(4);
DEFINE_ASAN_REPORT_LOAD_NOABORT(8);
DEFINE_ASAN_REPORT_LOAD_NOABORT(16);
DEFINE_ASAN_REPORT_STORE_NOABORT(1);
DEFINE_ASAN_REPORT_STORE_NOABORT(2);
DEFINE_ASAN_REPORT_STORE_NOABORT(4);
DEFINE_ASAN_REPORT_STORE_NOABORT(8);
DEFINE_ASAN_REPORT_STORE_NOABORT(16);

void __asan_report_load_n_noabort(UINTN addr, UINTN size)
{

}


void __asan_report_store_n_noabort(UINTN addr, UINTN size)
{

}

//
// Note: Using __builtin_return_address(1~n) in below code might cause CPU exception
// because the call stack during running don't always have n deep in fact. You can just
// remove the "Num2Str64bit ((unsigned long)__builtin_return_address(n),NumStr)" in
// below macro.
// But I still leave the __builtin_return_address(1~n) here to permit the execution
// stop intentionally when memory check fails, because I more hope to trace the call
// stack details info.
//
#define DEFINE_ASAN_LOAD(size)                      \
void __asan_load##size(unsigned long addr)          \
{                                                   \
}


#define DEFINE_ASAN_STORE(size)                     \
void __asan_store##size(unsigned long addr)         \
{                                                   \
}

#define DEFINE_ASAN_LOAD_NOABORT(size)                \
void __asan_load##size##_noabort(unsigned long addr)  \
{                                                   \
}


#define DEFINE_ASAN_STORE_NOABORT(size)                 \
void __asan_store##size##_noabort(unsigned long addr)   \
{                                                   \
}

DEFINE_ASAN_LOAD(1);
DEFINE_ASAN_LOAD(2);
DEFINE_ASAN_LOAD(4);
DEFINE_ASAN_LOAD(8);
DEFINE_ASAN_LOAD(16);
DEFINE_ASAN_STORE(1);
DEFINE_ASAN_STORE(2);
DEFINE_ASAN_STORE(4);
DEFINE_ASAN_STORE(8);
DEFINE_ASAN_STORE(16);
DEFINE_ASAN_LOAD_NOABORT(1);
DEFINE_ASAN_LOAD_NOABORT(2);
DEFINE_ASAN_LOAD_NOABORT(4);
DEFINE_ASAN_LOAD_NOABORT(8);
DEFINE_ASAN_LOAD_NOABORT(16);
DEFINE_ASAN_STORE_NOABORT(1);
DEFINE_ASAN_STORE_NOABORT(2);
DEFINE_ASAN_STORE_NOABORT(4);
DEFINE_ASAN_STORE_NOABORT(8);
DEFINE_ASAN_STORE_NOABORT(16);

UINTN __asan_region_is_poisoned(UINTN beg, UINTN size) {
  return 0;
}


void __asan_loadN_noabort(unsigned long addr, UINTN size)
{

}

void __asan_storeN_noabort(unsigned long addr, UINTN size)
{

}

void __asan_loadN(unsigned long addr, UINTN size)
{

}

void __asan_storeN(unsigned long addr, UINTN size)
{

}

//\llvm\projects\compiler-rt\lib\asan\asan_fake_stack.cc
// ---------------------- Interface ---------------- {{{1
int __asan_option_detect_stack_use_after_return = 0;
UINTN __asan_shadow_memory_dynamic_address = 0x10000000;

UINTN
EFIAPI
OnMalloc (
  IN UINTN  ID,
  IN UINTN  AllocationSize
  )
{
  //SerialOutput ("OnMalloc\n");
  return 0;
}

void
EFIAPI
OnFree (
  IN UINTN  ptr,
  IN UINTN  ID,
  IN UINTN  AllocationSize
  )
{
  //SerialOutput ("OnFree\n");
}

#define DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(class_id)                       \
  UINTN __asan_stack_malloc_##class_id(UINTN size) {                              \
    return OnMalloc(class_id, size);                                           \
  }                                                                            \
  void __asan_stack_free_##class_id(UINTN ptr, UINTN size) {                   \
    OnFree(ptr, class_id, size);                                               \
  }

DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(0)
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(1)
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(2)
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(3)
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(4)
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(5)
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(6)
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(7)
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(8)
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(9)
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(10)


void __asan_set_shadow_00(UINTN addr, UINTN size) {
  //REAL(memset)((void *)addr, 0, size);
}

void __asan_set_shadow_f1(UINTN addr, UINTN size) {
  //REAL(memset)((void *)addr, 0xf1, size);
}

void __asan_set_shadow_f2(UINTN addr, UINTN size) {
  //REAL(memset)((void *)addr, 0xf2, size);
}

void __asan_set_shadow_f3(UINTN addr, UINTN size) {
  //REAL(memset)((void *)addr, 0xf3, size);
}

void __asan_set_shadow_f5(UINTN addr, UINTN size) {
  //REAL(memset)((void *)addr, 0xf5, size);
}

void __asan_set_shadow_f8(UINTN addr, UINTN size) {
  //REAL(memset)((void *)addr, 0xf8, size);
}

//
// This structure is used to describe the source location of a place where
// global was defined.
typedef struct{
  const char *filename;
  int line_no;
  int column_no;
}__asan_global_source_location;

//
// This structure describes an instrumented global variable.
//
typedef struct  {
  UINTN beg;                // The address of the global.
  UINTN size;               // The original size of the global.
  UINTN size_with_redzone;  // The size with the redzone.
  const char *name;        // Name as a C string.
  const char *module_name; // Module name as a C string. This pointer is a
                           // unique identifier of a module.
  UINTN has_dynamic_init;   // Non-zero if the global has dynamic initializer.
  __asan_global_source_location *location;  // Source location of a global,
                                            // or NULL if it is unknown.
  UINTN odr_indicator;      // The address of the ODR indicator symbol.
}__asan_global;

typedef __asan_global Global;

void * Intrinsic_memset (void *dest, char ch, unsigned int count);
//D:\Project\LLVM\llvm\projects\compiler-rt\lib\asan\asan_poisoning.h
// Fast versions of PoisonShadow and PoisonShadowPartialRightRedzone that
// assume that memory addresses are properly aligned. Use in
// performance-critical code with care.
void
FastPoisonShadow(
  UINTN aligned_beg,
  UINTN aligned_size,
  UINT8 value
  )
{


}

void
FastPoisonShadowPartialRightRedzone(
  UINTN aligned_addr,
  UINTN size,
  UINTN size_with_redzone,
  UINT8 value
  )
{

}

UINTN
ComputePoolRightRedzoneSize(
  IN UINTN user_requested_size
  )
{
  UINTN rz_size =
    user_requested_size <= 64        - 16   ? 16 :
    user_requested_size <= 128       - 32   ? 32 :
    user_requested_size <= 512       - 64   ? 64 :
    user_requested_size <= 4096      - 128  ? 128 :
    user_requested_size <= (1 << 14) - 256  ? 256 :
    user_requested_size <= (1 << 15) - 512  ? 512 :
    user_requested_size <= (1 << 16) - 1024 ? 1024 : 2048;
  return rz_size;
}

//D:\Project\LLVM\llvm\projects\compiler-rt\lib\asan\asan_globals.cc
// void PoisonShadowForGlobal(const Global *g, UINT8 value) {
  // FastPoisonShadow(g->beg, g->size_with_redzone, value);
// }
void
PoisonPool(
  IN const UINTN Addr,
  IN UINTN Size,
  IN const UINT8 value
  )
{


}

void
UnpoisonPool(
  IN const UINTN Addr,
  IN UINTN Size
  )
{

}


void PoisonPages (
  IN const UINT64 Start,
  IN const UINTN  PageNum,
  IN const UINT8  Value
  )
{

}

void UnpoisonPages (
  IN const UINT64 Start,
  IN const UINTN  PageNum
  )
{

}


void PoisonGlobalRedZone(const __asan_global *g) {


}

// Register an array of globals.
void __asan_register_globals(__asan_global *globals, UINTN size) {

}


// Unregister an array of globals.
// We must do this when a shared objects gets dlclosed.
void __asan_unregister_globals(__asan_global *globals, UINTN n) {

}

void __asan_register_elf_globals(UINTN *flag, void *start, void *stop) {

}

void __asan_unregister_elf_globals(UINTN *flag, void *start, void *stop) {

}

void __asan_init() {

}

void __asan_version_mismatch_check_v8() {

}

void __asan_version_mismatch_check_v6() {

}

VOID *
EFIAPI
Intrinsic_CopyMem (
  OUT     VOID                      *DestinationBuffer,
  IN      CONST VOID                *SourceBuffer,
  IN      UINTN                     Length
  );

void * __asan_memcpy (void *dest, const void *src, unsigned int count)
{
  return Intrinsic_CopyMem (dest, src, (UINTN)count);
}

void * __asan_memset (void *dest, char ch, unsigned int count)
{
  return Intrinsic_memset (dest, ch, count);
}

void __asan_alloca_poison(UINTN addr, UINTN size) {

}

void __asan_allocas_unpoison(UINTN top, UINTN bottom) {

}

void __asan_handle_no_return() {

}

void __asan_poison_stack_memory(UINTN addr, UINTN size) {

}

void __asan_unpoison_stack_memory(UINTN addr, UINTN size) {

}

void __edk2_sanitizer_trap() {

}

struct TypeDescriptor {
  UINT16 TypeKind;
  UINT16 TypeInfo;
  char TypeName[1];
};

struct SourceLocation {
  const char *file_name;
  UINT32 line;
  UINT32 column;
};

struct OverflowDescData {
	struct SourceLocation Loc;
};

struct TypeMismatchData {
  struct SourceLocation Loc;
  struct TypeDescriptor *Type;
  unsigned char LogAlignment;
  unsigned char TypeCheckKind;
};

const char *TypeCheckKinds[] = {
    "load of", "store to", "reference binding to", "member access within",
    "member call on", "constructor call on", "downcast of", "downcast of",
    "upcast of", "cast to virtual base of", "_Nonnull binding to"
};


void __ubsan_handle_type_mismatch(struct TypeMismatchData *Data, UINTN Pointer) {

}

void __ubsan_handle_type_mismatch_v1(struct TypeMismatchData *Data, UINTN Pointer) {

}

void __ubsan_handle_type_mismatch_v1_abort(UINTN *Data, UINTN Pointer) {

}

struct shift_out_of_bounds_data {
  struct SourceLocation location;
  struct TypeDescriptor *lhs_type;
  struct TypeDescriptor *rhs_type;
};


void __ubsan_handle_shift_out_of_bounds(struct shift_out_of_bounds_data *Data, UINTN LHS, UINTN RHS) {

}

void __ubsan_handle_shift_out_of_bounds_abort(UINTN *Data, UINTN LHS, UINTN RHS) {

}

void __ubsan_handle_divrem_overflow(UINTN *Data, UINTN LHS, UINTN RHS) {

}

void __ubsan_handle_divrem_overflow_abort(UINTN *Data, UINTN LHS, UINTN RHS) {

}

void __ubsan_handle_out_of_bounds(UINTN *Data, UINTN Index) {

}

void __ubsan_handle_out_of_bounds_abort(UINTN *Data, UINTN Index) {

}

void __ubsan_handle_negate_overflow(UINTN *Data, UINTN OldVal) {

}

void __ubsan_handle_negate_overflow_abort(UINTN *Data, UINTN OldVal) {

}

void __ubsan_handle_builtin_unreachable(UINTN *Data) {

}

void __ubsan_handle_add_overflow(UINTN *Data, UINTN LHS, UINTN RHS) {

}

void __ubsan_handle_add_overflow_abort(UINTN *Data, UINTN LHS, UINTN RHS) {

}

void __ubsan_handle_sub_overflow(UINTN *Data, UINTN LHS, UINTN RHS) {

}

void __ubsan_handle_sub_overflow_abort(UINTN *Data, UINTN LHS, UINTN RHS) {

}

void __ubsan_handle_mul_overflow(UINTN *Data, UINTN LHS, UINTN RHS) {

}

void __ubsan_handle_mul_overflow_abort(UINTN *Data, UINTN LHS, UINTN RHS) {

}

void __ubsan_handle_pointer_overflow(struct OverflowDescData *Data, UINTN Base, UINTN Result) {

}

void __ubsan_handle_pointer_overflow_abort(struct OverflowDescData *Data, UINTN Base, UINTN Result) {

}

void __ubsan_handle_float_cast_overflow(UINTN *Data, UINTN From) {

}

void __sanitizer_cov_trace_pc(void)
{

}

//
// These symbols are provided in the GCC linker script.
//
extern void (*__preinit_array_start []) (int, char **, char **);
extern void (*__preinit_array_end []) (int, char **, char **);
extern void (*__init_array_start []) (int, char **, char **);
extern void (*__init_array_end []) (int, char **, char **);
extern void (*__fini_array_start []) (void);
extern void (*__fini_array_end []) (void);

RETURN_STATUS
EFIAPI
SetupAsanShadowMemory (
  VOID
  )
{
  EFI_HOB_GUID_TYPE     *GuidHob;
  ASAN_INFO             *AsanInfoPtr;

  GuidHob = GetFirstGuidHob (&gAsanInfoGuid);
  if (GuidHob == NULL) {
    asan_is_deactivated = TRUE;
    asan_inited = FALSE;
    mAsanShadowMemoryStart = 0;
    mAsanShadowMemorySize = 0;
    return RETURN_UNSUPPORTED;
  } 

  AsanInfoPtr = GET_GUID_HOB_DATA (GuidHob);
  asan_inited = (AsanInfoPtr->AsanInited == 0)? FALSE: TRUE;;
  asan_is_deactivated = (AsanInfoPtr->AsanActivated == 0)? TRUE: FALSE;
  mAsanShadowMemoryStart = AsanInfoPtr->AsanShadowMemoryStart;
  mAsanShadowMemoryStartPhy = AsanInfoPtr->AsanShadowMemoryStart;
  mAsanShadowMemorySize = AsanInfoPtr->AsanShadowMemorySize;
  mAsanShadowMemoryEnd = mAsanShadowMemoryStart + mAsanShadowMemorySize -1 ;
  mPhyMemoryEnd = mAsanShadowMemorySize * (SHADOW_GRANULARITY);

  __asan_shadow_memory_dynamic_address = mAsanShadowMemoryStart;


  CHAR8 NumStr[19];
  SerialOutput ("asan_inited = ");
  Num2Str64bit ( asan_inited , NumStr);
  SerialOutput (NumStr);
  SerialOutput ("\n");
  SerialOutput ("asan_is_deactivated = ");
  Num2Str64bit ( asan_is_deactivated , NumStr);
  SerialOutput (NumStr);
  SerialOutput ("\n");
  SerialOutput ("mAsanShadowMemoryStart = ");
  Num2Str64bit ( mAsanShadowMemoryStart , NumStr);
  SerialOutput (NumStr);
  SerialOutput ("\n");
  SerialOutput ("mAsanShadowMemorySize = ");
  Num2Str64bit ( mAsanShadowMemorySize , NumStr);
  SerialOutput (NumStr);
  SerialOutput ("\n");
  SerialOutput ("mPhyMemoryEnd = ");
  Num2Str64bit ( mPhyMemoryEnd , NumStr);
  SerialOutput (NumStr);
  SerialOutput ("\n");

  if (mAsanShadowMemorySize < 0x800000) { //8M shadow memory at least, map to 64M system memory
    asan_inited = FALSE;
    asan_is_deactivated = TRUE;
    SerialOutput ("mAsanShadowMemorySize is too small!\n");
    return RETURN_UNSUPPORTED;
  }

  return RETURN_SUCCESS;
}


RETURN_STATUS
EFIAPI
AsanLibNullConstructor (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                    Status;
  CHAR8                         NumStr[19];
  int                           size;
  SerialOutput ("AsanLibNullConstructor begin\n");
  SerialOutput ("Get hob of gAsanInfoGuid\n");

  if (AsanCtorFlag) {
    return RETURN_SUCCESS;//Status;
  } else {
    AsanCtorFlag = TRUE;
  }

  Status = SetupAsanShadowMemory();
  if (EFI_ERROR(Status)){
    return RETURN_SUCCESS;//Status;
  }

  size = __preinit_array_end - __preinit_array_start;
  SerialOutput ("AsanLibNullConstructor: preinit function pointers size = ");
  Num2Str64bit ( size , NumStr);
  SerialOutput (NumStr);
  SerialOutput ("\n");

  for (int i = 0; i < size; i++){
    (*__preinit_array_start [i]) (0, 0, 0);
  }

  size = __init_array_end - __init_array_start;
  SerialOutput ("AsanLibNullConstructor: init function pointers size = ");
  Num2Str64bit ( size , NumStr);
  SerialOutput (NumStr);
  SerialOutput ("\n");

  for (int i = 0; i < size; i++){
    (*__init_array_start [i]) (0, 0, 0);
  }

  SerialOutput ("AsanLibNullConstructor done\n");

  return RETURN_SUCCESS;
}
