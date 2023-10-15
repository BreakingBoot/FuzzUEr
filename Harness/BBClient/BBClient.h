#ifndef _BBCLIENT_H_
#define _BBCLIENT_H_

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include "../../MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.h"
#include <Library/BaseLib.h>
#include <PiDxe.h>
#include <Protocol/LoadedImage.h>
#include "../../ShellPkg/Include/Protocol/EfiShellInterface.h"
#include <Protocol/FirmwareVolume2.h>
#include <Protocol/ShellParameters.h>
#include <Library/PcdLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Guid/DxeServices.h>
#include <Protocol/VariableWrite.h>
#include <Protocol/FaultTolerantWrite.h>
#include <Protocol/FirmwareVolumeBlock.h>
#include <Protocol/Variable.h>
#include <Protocol/VariableLock.h>
#include <Protocol/VarCheck.h>
#include <Library/HobLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/DebugLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/SynchronizationLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/AuthVariableLib.h>
#include <Library/VarCheckLib.h>
#include <Library/VariableFlashInfoLib.h>
#include <Library/SafeIntLib.h>
#include <Guid/GlobalVariable.h>
#include <Guid/EventGroup.h>
#include <Guid/VariableFormat.h>
#include <Guid/SystemNvDataGuid.h>
#include <Guid/FaultTolerantWrite.h>
#include <Guid/VarErrorFlag.h>
#include <Protocol/GuidedSectionExtraction.h>
#include <Protocol/DevicePath.h>
#include <Protocol/Runtime.h>
#include <Protocol/LoadFile.h>
#include <Protocol/LoadFile2.h>
#include <Protocol/DriverBinding.h>
#include <Protocol/PlatformDriverOverride.h>
#include <Protocol/Timer.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/Bds.h>
#include <Protocol/RealTimeClock.h>
#include <Protocol/WatchdogTimer.h>
#include <Protocol/MonotonicCounter.h>
#include <Protocol/StatusCode.h>
#include <Protocol/Decompress.h>
#include <Protocol/LoadPe32Image.h>
#include <Protocol/Security.h>
#include <Protocol/Security2.h>
#include <Protocol/Reset.h>
#include <Protocol/Cpu.h>
#include <Protocol/Metronome.h>
#include <Protocol/Capsule.h>
#include <Protocol/BusSpecificDriverOverride.h>
#include <Protocol/DriverFamilyOverride.h>
#include <Protocol/TcgService.h>
#include <Protocol/HiiPackageList.h>
#include <Protocol/SmmBase2.h>
#include <Protocol/PeCoffImageEmulator.h>
#include <Guid/MemoryTypeInformation.h>
#include <Guid/FirmwareFileSystem2.h>
#include <Guid/FirmwareFileSystem3.h>
#include <Guid/HobList.h>
#include <Guid/DebugImageInfoTable.h>
#include <Guid/FileInfo.h>
#include <Guid/Apriori.h>
#include <Guid/MemoryAllocationHob.h>
#include <Guid/EventLegacyBios.h>
#include <Guid/EventExitBootServiceFailed.h>
#include <Guid/LoadModuleAtFixedAddress.h>
#include <Guid/IdleLoopEvent.h>
#include <Guid/VectorHandoffTable.h>
#include <Ppi/VectorHandoffInfo.h>
#include <Guid/MemoryProfile.h>
#include <Library/DxeCoreEntryPoint.h>
#include <Library/PerformanceLib.h>
#include <Library/UefiDecompressLib.h>
#include <Library/ExtractGuidedSectionLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/PeCoffLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/PeCoffExtraActionLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/ReportStatusCodeLib.h>
#include <Library/DxeServicesLib.h>
#include <Library/DebugAgentLib.h>
#include <Library/CpuExceptionHandlerLib.h>


#define PROCESS_FIRMWARE_VOLUME 0
#define EVENT 1
#define LOAD_IMAGE 2
#define PROTOCOL 4
#define MEMORY 3

#endif