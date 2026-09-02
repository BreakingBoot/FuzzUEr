#include <asm/msr.h>
#include <asm/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/slab.h>

#include "smi_types.h"
#include "known_guids.h"
#include "address_remapping.h"

#include <linux/module.h>
#include <linux/io.h>
#include <linux/pci.h>

struct smram_bounds
{
    uint32_t base;
    uint32_t limit;
};

static struct smram_bounds get_smram_bounds(void)
{
    struct pci_dev *dev = NULL;
    uint32_t smbase, smlimit;
    struct smram_bounds bounds = {0, 0};

    // Find the Host Bridge device (Device 0, Function 0 on Intel chipsets)
    dev = pci_get_device(PCI_VENDOR_ID_INTEL, PCI_ANY_ID, dev);
    if (!dev)
    {
        pr_err("Failed to find the Host Bridge device.\n");
        return bounds;
    }

    // Read the TSEG base and limit registers.
    // NOTE: The exact register offsets (e.g., 0xB0 and 0xB4) might vary
    // depending on the chipset, and you might need to check the datasheet.
    pci_read_config_dword(dev, 0xB0, &smbase);
    pci_read_config_dword(dev, 0xB4, &smlimit);

    bounds.base = smbase & 0xFFF00000;   // Mask to get the base address
    bounds.limit = smlimit & 0xFFF00000; // Mask to get the limit address

    pci_dev_put(dev); // Decrement the refcount for the device

    return bounds;
}

// credit: https://www.willsroot.io/2023/08/smm-diary-writeup.html
void log_smis(void)
{
    uint64_t val = 0;
    rdmsrl(MSR_SMI_COUNT, val);
    printk(KERN_INFO "SMI_COUNT: 0x%llx\n", val);
}
phys_addr_t get_smram_base(void)
{
    return get_smram_bounds().base;
}

void trigger_smi(void)
{
    log_smis();
    asm volatile(
        ".intel_syntax noprefix;"
        "xor eax, eax;"
        "outb 0xb3, al;"
        "outb 0xb2, al;"
        ".att_syntax;" ::: "rax");
    log_smis();
}

void trigger_b2smi(void)
{
    log_smis();
    asm volatile(
        ".intel_syntax noprefix;"
        "xor eax, eax;"
        "outb 0xb3, al;"
        "mov al, 0xb4;"
        "outb 0xb2, al;"
        ".att_syntax;" ::: "rax");
    log_smis();
}

SMM_CORE_PRIVATE_DATA *find_smm_core_private_data(void *mapped_region_start, void *mapped_region_end)
{
    UINT32 signature = SMM_CORE_PRIVATE_DATA_SIGNATURE;
    void *smm_core_private_data;

    UINT32 *ptr = ((UINT32 *)mapped_region_end) - 1;
    if (mapped_region_start == NULL || mapped_region_end == NULL)
    {
        printk(KERN_ALERT "mapped_region_start or mapped_region_end is NULL\n");
        return NULL;
    }
    if (mapped_region_start > mapped_region_end)
    {
        printk(KERN_ALERT "mapped_region_start > mapped_region_end\n");
        return NULL;
    }
    if (((UINTN)mapped_region_start & 0xfff) != 0x0)
    {
        printk(KERN_ALERT "mapped_region_start is not page aligned\n");
        return NULL;
    }
    if (((UINTN)mapped_region_end & 0xfff) != 0x0)
    {
        printk(KERN_ALERT "mapped_region_end=%px is not page aligned\n", mapped_region_end);
        return NULL;
    }
    // scan the mapped_smm_region for the SMM_CORE_PRIVATE_DATA_SIGNATURE from the end
    // of the region to the beginning
    // if found, return the address of the SMM_CORE_PRIVATE_DATA
    // else return NULL
    smm_core_private_data = NULL;
    while (ptr > (UINT32 *)mapped_region_start)
    {
        ptr--;
        if (*ptr != 0 && *ptr != 0xafafafaf)
        {
            // printk(KERN_INFO "0x%px: 0x%x (%c%c%c%c)\n", ptr, *ptr, *(char*)ptr, *((char*)ptr + 1), *((char*)ptr + 2), *((char*)ptr + 3));
        }
        if (*ptr == signature)
        {
            off_t off_from_start = (uint64_t)ptr - (uint64_t)mapped_region_start;
            off_t off_from_end = (uint64_t)mapped_region_end - (uint64_t)ptr;
            printk(KERN_INFO "found SMM_CORE_PRIVATE_DATA_SIGNATURE at %px\n", ptr);
            printk(KERN_INFO "SMM_CORE_PRIVATE_DATA is 0x%lx bytes from the start of the mapped SMM region\n", off_from_start);
            printk(KERN_INFO "SMM_CORE_PRIVATE_DATA is -0x%lx bytes from the end of the mapped SMM region\n", off_from_end);
            smm_core_private_data = ptr;
        }
    }
    if (smm_core_private_data != NULL)
    {
        printk(KERN_INFO "SMM_CORE_PRIVATE_DATA found at %px, ptr=%px at the end, mapped_region_start=%px, mapped_region_end=%px\n", smm_core_private_data, ptr, mapped_region_start, mapped_region_end);
        return (SMM_CORE_PRIVATE_DATA *)smm_core_private_data;
    }
    printk(KERN_ALERT "SMM_CORE_PRIVATE_DATA_SIGNATURE not found\n");
    return NULL;
}

void dump_smm_core_private_data(SMM_CORE_PRIVATE_DATA *p)
{
    if (p == NULL)
    {
        printk(KERN_ALERT "SMM_CORE_PRIVATE_DATA is NULL\n");
        return;
    }
    /*
    typedef struct {
    UINTN                   Signature;
    EFI_HANDLE              SmmIplImageHandle;
    UINTN                   SmramRangeCount;
    EFI_SMRAM_DESCRIPTOR    *SmramRanges;
    EFI_SMM_ENTRY_POINT      SmmEntryPoint;
    BOOLEAN                  SmmEntryPointRegistered;
    BOOLEAN                  InSmm;
    void                     *Smst;
    VOID                     *CommunicationBuffer;
    UINTN                    BufferSize;
    EFI_STATUS               ReturnStatus;
    EFI_PHYSICAL_ADDRESS     PiSmmCoreImageBase;
    UINT64                   PiSmmCoreImageSize;
    EFI_PHYSICAL_ADDRESS     PiSmmCoreEntryPoint;
    } SMM_CORE_PRIVATE_DATA;
    */
    printk(KERN_INFO "SMM_CORE_PRIVATE_DATA:\n");
    printk(KERN_INFO "  Signature: 0x%lx (%c%c%c%c)\n", p->Signature, *((char *)&p->Signature), *((char *)&p->Signature + 1), *((char *)&p->Signature + 2), *((char *)&p->Signature + 3));
    printk(KERN_INFO "  SmmIplImageHandle: 0x%llx\n", p->SmmIplImageHandle);
    printk(KERN_INFO "  SmramRangeCount: 0x%lx\n", p->SmramRangeCount);
    printk(KERN_INFO "  SmramRanges: 0x%px\n", p->SmramRanges);
    printk(KERN_INFO "  SmmEntryPoint: 0x%px\n", p->SmmEntryPoint);
    printk(KERN_INFO "  SmmEntryPointRegistered: %s\n", p->SmmEntryPointRegistered ? "true" : "false");
    printk(KERN_INFO "  InSmm: %s\n", p->InSmm ? "true" : "false");
    printk(KERN_INFO "  Smst: 0x%px\n", p->Smst);
    printk(KERN_INFO "  CommunicationBuffer: 0x%px\n", p->CommunicationBuffer);
    printk(KERN_INFO "  BufferSize: 0x%lx\n", p->BufferSize);
    printk(KERN_INFO "  ReturnStatus: 0x%llx\n", p->ReturnStatus);
    printk(KERN_INFO "  PiSmmCoreImageBase: 0x%llx\n", p->PiSmmCoreImageBase);
    printk(KERN_INFO "  PiSmmCoreImageSize: 0x%llx\n", p->PiSmmCoreImageSize);
    printk(KERN_INFO "  PiSmmCoreEntryPoint: 0x%llx\n", p->PiSmmCoreEntryPoint);
}
int guid_to_string(char *out, size_t buflen, EFI_GUID *g)
{
    char buf[0x100];
    snprintf(buf, 0x100, "%08X-%02X-%02X-%02x%02x%02x%02x", g->Data1, g->Data2, g->Data3, g->Data4[0], g->Data4[1], g->Data4[2], g->Data4[3]);
    return snprintf(out, buflen, "%s%02x%02x%02x%02x", buf, g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
}
void dump_commbuffer(EFI_MM_COMMUNICATE_HEADER *p)
{
    char guidbuf[0x100];
    if (p == NULL)
    {
        printk(KERN_ALERT "EFI_MM_COMMUNICATE_HEADER is NULL\n");
        return;
    }
    guid_to_string(guidbuf, 0x100, &p->HeaderGuid);
    printk(KERN_INFO "EFI_MM_COMMUNICATE_HEADER:\n");
    printk(KERN_INFO "  HeaderGuid: %s\n", guidbuf);
    printk(KERN_INFO "  MessageLength: 0x%lx\n", p->MessageLength);
    printk(KERN_INFO "  Data: 0x%px\n", p->Data);
}

void hexdump(void *ptr, size_t len)
{
    char line[0x300];
    while (len > 0)
    {
        sprintf(line, "0x%px: ", ptr);
        for (size_t i = 0; i < 16; i++)
        {
            if (i < len)
            {
                sprintf(line + strlen(line), "%02x ", *((uint8_t *)ptr + i));
            }
            else
            {
                sprintf(line + strlen(line), "   ");
            }
        }
        for (size_t i = 0; i < 16; i++)
        {
            if (i < len)
            {
                uint8_t c = *((uint8_t *)ptr + i);
                if (c >= 0x20 && c <= 0x7e)
                {
                    sprintf(line + strlen(line), "%c", c);
                }
                else
                {
                    sprintf(line + strlen(line), ".");
                }
            }
            else
            {
                sprintf(line + strlen(line), " ");
            }
        }
        printk(KERN_INFO "%s\n", line);
        ptr += 16;
        len -= 16;
    }
}


bool map_smm_shared_region(phys_addr_t start, phys_addr_t end)
{
    off_t offset = 0x40000;
    if ((end & 0xfff) == 0xfff)
    {
        end += 1;
    }

    if (remapped_buffer_addr(start, end))
    {
        printk(KERN_ALERT "Failed to map reserved region %llx-%llx, retrying with skip offset\n", start, end);
        return true;
    }

    while (start + offset < end && !remapped_buffer_addr(start + offset, end))
    { // if it fails, try again with a different offset
        printk(KERN_ALERT "Failed to map reserved region %llx-%llx with skip offset %lx\n", start, end, offset);
        offset <<= 1;
    }
    if (start + offset >= end)
    {
        printk(KERN_ALERT "Failed to map reserved region %llx-%llx\n", start, end);
        return false;
    }
    printk(KERN_INFO "Mapped reserved region %llx-%llx with skip offset %lx\n", start, end, offset);
    return true;
}

struct smm_data
{
    phys_addr_t                 smmc_phys_addr;
    SMM_CORE_PRIVATE_DATA      *smmc_remapped_addr;
    phys_addr_t                 commbuffer_phys_addr;
    EFI_SMM_COMMUNICATE_HEADER *commbuffer_remapped_addr;
    phys_addr_t                 buffer_size_phys_addr;
    UINTN                      *buffer_size_remapped_addr;
};
bool find_smmc_private_and_commbuffer(struct smm_data *smm_data_out)
{
    phys_addr_t smmc_phys_addr = 0;
    EFI_SMM_COMMUNICATE_HEADER *commbuffer = NULL;
    SMM_CORE_PRIVATE_DATA *smm_private_data = NULL;
    SMM_CORE_PRIVATE_DATA *cur_smm_private_data = NULL;
    struct remapped_region *region;
    FOR_EACH_REMAPPED_REGION(region)
    {
        printk(KERN_INFO "Looking for smmcs in remapped region %llx-%llx => %px-%px\n",
               region->start, region->end, region->mapped_start, region->mapped_end);

        cur_smm_private_data = find_smm_core_private_data(region->mapped_start, region->mapped_end);
        if (cur_smm_private_data)
        {
            smmc_phys_addr = ((void *)cur_smm_private_data - region->mapped_start) + region->start;
            printk(KERN_INFO "smm_private_data @ mapped address %px, physical address %llx\n",
                   cur_smm_private_data,
                   smmc_phys_addr);
            smm_private_data = cur_smm_private_data;
            hexdump(smm_private_data, 0x100);
        }
        else
        {
            printk(KERN_INFO "smm_private_data = %px not found in this region\n", cur_smm_private_data);
        }
    }
    printk(KERN_INFO "smm_private_data = %px, smmc_phys_addr = %llx\n", smm_private_data, smmc_phys_addr);
    dump_smm_core_private_data(smm_private_data);
    hexdump((void *)smm_private_data, 0x200);

    smm_private_data->CommunicationBuffer = (void *)(((UINTN)smmc_phys_addr + sizeof(SMM_CORE_PRIVATE_DATA) + 0xf) & ~0xf);
    commbuffer = (EFI_SMM_COMMUNICATE_HEADER *)remapped_buffer_addr(
        (phys_addr_t)smm_private_data->CommunicationBuffer,
        smm_private_data->BufferSize);

    if (commbuffer != (void *)(((UINTN)(smm_private_data + 1) + 0xf) & ~0xf))
    {
        printk(KERN_ALERT "commbuffer != smm_private_data + 1\n");
        return -1;
    }
    printk(KERN_INFO "commbuffer = %px, offset from smm_private_data = %ld\n", commbuffer, (void *)commbuffer - (void *)smm_private_data);
    smm_data_out->smmc_phys_addr = smmc_phys_addr;
    smm_data_out->smmc_remapped_addr = smm_private_data;
    smm_data_out->commbuffer_phys_addr = (phys_addr_t)smm_private_data->CommunicationBuffer;
    smm_data_out->commbuffer_remapped_addr = commbuffer;
    smm_data_out->buffer_size_phys_addr = ((void*)&smm_private_data->BufferSize - (void *)smm_private_data) + smmc_phys_addr;
    smm_data_out->buffer_size_remapped_addr = &smm_private_data->BufferSize;
    return true;
}




#define EFI_RUNTIME_SERVICES_SIGNATURE  SIGNATURE_64 ('R','U','N','T','S','E','R','V')
#define EFI_BOOT_SERVICES_SIGNATURE  SIGNATURE_64 ('B','O','O','T','S','E','R','V')

void *find_64bit_signature(void *mapped_region_start, void *mapped_region_end, UINT64 signature)
{
    char signature_string[0x200];
    void* sig_found = NULL;
    UINT64 *ptr = ((UINT64 *)mapped_region_end) - 1;
    if (mapped_region_start == NULL || mapped_region_end == NULL)
    {
        printk(KERN_ALERT "mapped_region_start or mapped_region_end is NULL\n");
        return NULL;
    }
    if (mapped_region_start > mapped_region_end)
    {
        printk(KERN_ALERT "mapped_region_start > mapped_region_end\n");
        return NULL;
    }
    if (((UINTN)mapped_region_start & 0xfff) != 0x0)
    {
        printk(KERN_ALERT "mapped_region_start is not page aligned\n");
        return NULL;
    }
    if (((UINTN)mapped_region_end & 0xfff) != 0x0)
    {
        printk(KERN_ALERT "mapped_region_end=%px is not page aligned\n", mapped_region_end);
        return NULL;
    }
    // scan the mapped_smm_region for the SMM_CORE_PRIVATE_DATA_SIGNATURE from the end
    // of the region to the beginning
    // if found, return the address of the SMM_CORE_PRIVATE_DATA
    // else return NULL

    memset(signature_string, 0, sizeof(signature_string));
    sprintf(signature_string, "%c%c%c%c%c%c%c%c",
        (char)(signature & 0xff),
        (char)((signature >> 8) & 0xff),
        (char)((signature >> 16) & 0xff),
        (char)((signature >> 24) & 0xff),
        (char)((signature >> 32) & 0xff),
        (char)((signature >> 40) & 0xff),
        (char)((signature >> 48) & 0xff),
        (char)((signature >> 56) & 0xff)
    );
    sig_found = NULL;
    while (ptr > (UINT64 *)mapped_region_start)
    {
        ptr--;
        // if (*ptr != 0 && *ptr != 0xafafafafafafafaf)
        // {
        //     // printk(KERN_INFO "0x%px: 0x%x (%c%c%c%c)\n", ptr, *ptr, *(char*)ptr, *((char*)ptr + 1), *((char*)ptr + 2), *((char*)ptr + 3));
        // }
        if (*ptr == signature)
        {
            off_t off_from_start = (uint64_t)ptr - (uint64_t)mapped_region_start;
            off_t off_from_end = (uint64_t)mapped_region_end - (uint64_t)ptr;

            printk(KERN_INFO "found UINT64 signature 0x%llx(%s) at %px, 0x%lx bytes from the start, -0x%lx bytes from the end\n", signature, signature_string, ptr, off_from_start, off_from_end);
            sig_found = ptr;
        }
    }
    if (sig_found != NULL)
    {
        printk(KERN_INFO "UINT64 signature 0x%llx(%s) found at %px\n", signature, signature_string, sig_found);
        return (void*)sig_found;
    }
    printk(KERN_ALERT "UINT64 signature 0x%llx(%s) not found\n", signature, signature_string);
    return NULL;
}

struct uefi_services {
    EFI_RUNTIME_SERVICES *runtime_services;
    phys_addr_t runtime_services_phys_addr;
    EFI_BOOT_SERVICES *boot_services;
    phys_addr_t boot_services_phys_addr;
};
bool find_runtime_services(struct uefi_services *uefi_services_out)
{
    void *cur_found = NULL;
    struct remapped_region *region;

    memset(uefi_services_out, 0, sizeof(struct uefi_services));
    FOR_EACH_REMAPPED_REGION(region)
    {
        printk(KERN_INFO "Looking for runtime services in remapped region %llx-%llx => %px-%px\n",
               region->start, region->end, region->mapped_start, region->mapped_end);

        cur_found = find_64bit_signature(region->mapped_start, region->mapped_end, EFI_RUNTIME_SERVICES_SIGNATURE);
        if (cur_found)
        {
            uefi_services_out->runtime_services_phys_addr = ((void *)cur_found - region->mapped_start) + region->start;
            printk(KERN_INFO "runtime_services @ mapped address %px, physical address %llx\n",
                   cur_found,
                   uefi_services_out->runtime_services_phys_addr);
            uefi_services_out->runtime_services = cur_found;
        }
        else
        {
            printk(KERN_INFO "runtime_services = %px not found in this region\n", cur_found);
        }

        cur_found = find_64bit_signature(region->mapped_start, region->mapped_end, EFI_BOOT_SERVICES_SIGNATURE);
        if (cur_found)
        {
            uefi_services_out->boot_services_phys_addr = ((void *)cur_found - region->mapped_start) + region->start;
            printk(KERN_INFO "boot_services @ mapped address %px, physical address %llx\n",
                   cur_found,
                   uefi_services_out->boot_services_phys_addr);
            uefi_services_out->boot_services = cur_found;
        }
        else
        {
            printk(KERN_INFO "boot_services = %px not found in this region\n", cur_found);
        }
    }
    if (uefi_services_out->runtime_services == NULL)
    {
        printk(KERN_ALERT "runtime_services not found\n");
        return false;
    }
    if (uefi_services_out->runtime_services->Hdr.Signature != EFI_RUNTIME_SERVICES_SIGNATURE)
    {
        printk(KERN_ALERT "runtime_services->Hdr.Signature != EFI_RUNTIME_SERVICES_SIGNATURE\n");
        return false;
    }
    if (uefi_services_out->boot_services == NULL)
    {
        printk(KERN_ALERT "boot_services not found\n");
        return false;
    }
    if (uefi_services_out->boot_services->Hdr.Signature != EFI_BOOT_SERVICES_SIGNATURE)
    {
        printk(KERN_ALERT "boot_services->Hdr.Signature != EFI_BOOT_SERVICES_SIGNATURE\n");
        return false;
    }
    return true;
}