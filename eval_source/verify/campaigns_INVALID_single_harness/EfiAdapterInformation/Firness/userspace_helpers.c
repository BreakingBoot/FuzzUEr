#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/efi.h>
#include "include/smm_context.h"
#include "include/known_guids.h"

static unsigned long efi_mm_addr = 0;
static struct mm_struct *efi_prev_mm;
static unsigned long (*my_kallsyms_lookup_name)(const char *name);
static void (*my_switch_mm)(struct mm_struct *prev, struct mm_struct *next, struct task_struct *tsk);

// https://nskernel.gitbook.io/kernel-play-guide/accessing-the-non-exported-in-modules
static void *lookup_kallsyms_lookup_name(void)
{
	struct kprobe kp;
	unsigned long addr;

	memset(&kp, 0, sizeof(struct kprobe));
	kp.symbol_name = "kallsyms_lookup_name";
	if (register_kprobe(&kp) < 0) {
		return 0;
	}
	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return (void *)addr;
}

static void efi_enter_mm(void)
{
	efi_prev_mm = current->active_mm;
	current->mm = (struct mm_struct *)efi_mm_addr;
	current->active_mm = (struct mm_struct *)efi_mm_addr;
	my_switch_mm(efi_prev_mm, (struct mm_struct *)efi_mm_addr, NULL);
}

static void efi_leave_mm(void)
{
	current->mm = efi_prev_mm;
	current->active_mm = efi_prev_mm;
	my_switch_mm((struct mm_struct *)efi_mm_addr, efi_prev_mm, NULL);
}

//static int maybe_efi_ptr(u64 ptr)
//{
//	return ptr >= 0x7E000000 && ptr < 0x80000000;
//}

static SMM_CORE_PRIVATE_DATA *find_smm_core_private_data(void)
{
	efi_memory_desc_t *md;

	for_each_efi_memory_desc(md) {
		printk("md: %lx, phys_addr: %lx, virt_addr: %lx, num_pages: %d\n", (unsigned long)md, (unsigned long)md->phys_addr, (unsigned long)md->virt_addr, (int)md->num_pages);
		u64 end = md->phys_addr + md->num_pages * PAGE_SIZE;
		for(u64 addr = md->phys_addr; addr < end; addr += 0x8) {
			u32 *ptr = (u32*)addr;
            if (*ptr == 0x636d6d73) {
				printk(KERN_INFO "Found smmc: %llx\n", addr);
				return (void *)(addr);
			}
		}
	}
	return NULL;
}

static void *prepare_comm_buff(void)
{
	efi_memory_desc_t *md;
	u64 max_num_pages = 0;
	u64 min_addr = -1;


	for_each_efi_memory_desc(md) {
		printk("md: %lx, phys_addr: %lx, virt_addr: %lx, num_pages: %d\n", (unsigned long)md, (unsigned long)md->phys_addr, (unsigned long)md->virt_addr, (int)md->num_pages);
		if (md->num_pages > max_num_pages) {
			max_num_pages = md->num_pages;
			min_addr = md->phys_addr;
		} else if (md->num_pages == max_num_pages && md->phys_addr < min_addr) {
			min_addr = md->phys_addr;
		}
	}

	return (void *)min_addr;
}

int smm_enter_context(smm_data_t *smm_data)
{
	memset(smm_data, 0, sizeof(*smm_data));

	my_kallsyms_lookup_name = lookup_kallsyms_lookup_name();
	if (my_kallsyms_lookup_name == NULL) {
		printk(KERN_ERR "fail to find kallsyms_lookup_name...");
		return -EINVAL;
	}
	efi_mm_addr = my_kallsyms_lookup_name("efi_mm");
	if (efi_mm_addr == 0) {
		printk(KERN_ERR "fail to find efi_mm...");
		return -EINVAL;
	}
	my_switch_mm = (void *)my_kallsyms_lookup_name("switch_mm");
	if (my_switch_mm == 0) {
		printk(KERN_ERR "fail to find switch_mm...");
		return -EINVAL;
	}

	efi_enter_mm();

	smm_data->core = find_smm_core_private_data();
	if (smm_data->core == NULL) {
		printk(KERN_ERR "fail to find smm_data->core...");
		goto leave_mm;
	}

	// prepare a huge commbuff, it cannot be something from __get_free_pages, or it will
	// trigger a sanity check in SmmIsBufferOutsideSmmValid in EDK2
	//void *comm_buff = (void *)__get_free_pages(GFP_KERNEL, 4);
	//smm_data->comm_buff = comm_buff;
	//smm_data->comm_buff_phys_addr = __pa(comm_buff);

	//smm_data->comm_buff = smm_data->core + sizeof(*smm_data->core);
	//smm_data->comm_buff_phys_addr = (u64)smm_data->comm_buff;

	//smm_data->comm_buff = (void*)0x7e8ed000; // FIXME: this is a value extracted from efi.memmap
	//smm_data->comm_buff_phys_addr = (u64)smm_data->comm_buff;

	smm_data->comm_buff = prepare_comm_buff(); // FIXME: this is a value extracted from efi.memmap
	smm_data->comm_buff_phys_addr = (u64)(smm_data->comm_buff);

	return 0;

leave_mm:
	efi_leave_mm();
	return -EINVAL;
}

void smm_leave_context(smm_data_t *smm_data)
{
	memset(smm_data, 0, sizeof(*smm_data));
	efi_leave_mm();
}

static void trigger_smi(void)
{
	//log_smis();
	asm volatile(
		".intel_syntax noprefix;"
		"xor eax, eax;"
		"outb 0xb3, al;"
		"outb 0xb2, al;"
		".att_syntax;" ::: "rax");
	//log_smis();
}

void smm_call_smi(smm_data_t *smm_data, EFI_GUID *CommGuid, void *data, size_t size)
{
	memcpy(smm_data->comm_buff, CommGuid, sizeof(EFI_GUID));
	//memcpy(smm_data->comm_buff, &gEfiSmmVariableProtocolGuid, sizeof(gEfiSmmVariableProtocolGuid));
	*(UINTN*)(smm_data->comm_buff+sizeof(EFI_GUID)) = (UINTN)size;
	memcpy(smm_data->comm_buff+offsetof(EFI_MM_COMMUNICATE_HEADER, Data), data, size);

	smm_data->core->CommunicationBuffer = (void *)smm_data->comm_buff_phys_addr;
	smm_data->core->BufferSize = size+offsetof(EFI_MM_COMMUNICATE_HEADER, Data);

	trigger_smi();
}


static void trigger_smi_data(u8 data)
{
	//log_smis();
    asm volatile(
        ".intel_syntax noprefix;"
        "mov al, %0;"
        "outb 0xb3, al;"
        "xor eax, eax;"
        "outb 0xb2, al;"
        ".att_syntax;"
        :: "r" (data)
        : "rax"
    );
}

void smm_call_smi_data(smm_data_t *smm_data, EFI_GUID *CommGuid, u8 port_data, void *data, size_t size)
{
	memcpy(smm_data->comm_buff, CommGuid, sizeof(EFI_GUID));
	//memcpy(smm_data->comm_buff, &gEfiSmmVariableProtocolGuid, sizeof(gEfiSmmVariableProtocolGuid));
	*(UINTN*)(smm_data->comm_buff+sizeof(EFI_GUID)) = (UINTN)size;
	memcpy(smm_data->comm_buff+offsetof(EFI_MM_COMMUNICATE_HEADER, Data), data, size);

	smm_data->core->CommunicationBuffer = (void *)smm_data->comm_buff_phys_addr;
	smm_data->core->BufferSize = size+offsetof(EFI_MM_COMMUNICATE_HEADER, Data);

	trigger_smi_data(port_data);
}

static void trigger_smi_data_cmd(u8 data, u8 cmd)
{
	//log_smis();
    asm volatile(
        ".intel_syntax noprefix;"
        "mov al, %0;"
        "outb 0xb3, al;"
        "mov al, %1;"
        "outb 0xb2, al;"
        ".att_syntax;"
        :: "r" (data), "r" (cmd)
        : "rax"
    );
}

void smm_call_smi_data_cmd(smm_data_t *smm_data, EFI_GUID *CommGuid, u8 port_data, u8 port_cmd, void *data, size_t size)
{
	memcpy(smm_data->comm_buff, CommGuid, sizeof(EFI_GUID));
	//memcpy(smm_data->comm_buff, &gEfiSmmVariableProtocolGuid, sizeof(gEfiSmmVariableProtocolGuid));
	*(UINTN*)(smm_data->comm_buff+sizeof(EFI_GUID)) = (UINTN)size;
	memcpy(smm_data->comm_buff+offsetof(EFI_MM_COMMUNICATE_HEADER, Data), data, size);

	smm_data->core->CommunicationBuffer = (void *)smm_data->comm_buff_phys_addr;
	smm_data->core->BufferSize = size+offsetof(EFI_MM_COMMUNICATE_HEADER, Data);

	trigger_smi_data_cmd(port_data, port_cmd);
}

// amazing blog post, credit: https://nixhacker.com/digging-into-smm/


#define DRAM_REGISTER_SMRAMC 0x88
#define DRAM_REGISTER_BDSM 0xb0
#define DRAM_REGISTER_BGSM 0xb4
#define DRAM_REGISTER_TSEGMB 0xb8
/*
 * get_dram_register
 *
 * This function will get the SMRAMC register from the DRAM controller
 * and print out the value of G_SMRAME (bit 3) to the kernel log and
 * return it to the caller.
 */
int get_dram_register(int reg)
{
	struct pci_dev *dev;
	uint8_t pci_data;
    printk(KERN_INFO "Hello world.\n");
    //get pci device
    dev = pci_get_device(0x8086, 0x0a04, NULL); // TODO: fix this so it works in qemu
    if (!dev)
    {
		printk(KERN_INFO "FAILED to get pci device\n");
		pci_dev_put(dev);
		return -ENODEV;
	}
	printk(KERN_INFO "Attached to the pci device\n");
	//Offset 0x88 in DRAM controller
	pci_read_config_byte(dev, reg, &pci_data);
	printk(KERN_INFO "SMRAMC data recieved is 0x%x.\n", pci_data);


	// Bit 3 in SMRAMC is G_SMRAME
	pci_data = pci_data >> 3;
	pci_data = pci_data & 0x1;
	printk(KERN_INFO "G_SMRAME is set to %x.\n", pci_data);

	//cleanup after use
	pci_dev_put(dev);
    return  pci_data;
}
#define SMRAMC_C_BASE_SEGMENT(x) ((x) & 0x7)
#define SMRAMC_G_SMRAME(x) (((x) >> 3) & 1)
#define SMRAMC_D_LCK(x) (((x) >> 4) & 1)
#define SMRAMC_D_CLS(x) (((x) >> 5) & 1)
#define SMRAMC_D_OPEN(x) (((x) >> 6) & 1)
#define SMRAMC_D_SMRAM(x) (((x) >> 7) & 1)

void dump_smramc_register(void)
{
    int smramc = get_dram_register(DRAM_REGISTER_SMRAMC);
    if (smramc < 0)
    {
        printk(KERN_INFO "FAILED to get smramc register\n");
        return;
    }
    printk(KERN_INFO "SMRAMC register: 0x%x\n", smramc);
    printk(KERN_INFO "SMRAMC_C_BASE_SEGMENT: 0x%x\n", SMRAMC_C_BASE_SEGMENT(smramc));
    printk(KERN_INFO "SMRAMC_G_SMRAME: 0x%x\n", SMRAMC_G_SMRAME(smramc));
    printk(KERN_INFO "SMRAMC_D_LCK: 0x%x\n", SMRAMC_D_LCK(smramc));
    printk(KERN_INFO "SMRAMC_D_CLS: 0x%x\n", SMRAMC_D_CLS(smramc));
    printk(KERN_INFO "SMRAMC_D_OPEN: 0x%x\n", SMRAMC_D_OPEN(smramc));
    printk(KERN_INFO "SMRAMC_D_SMRAM: 0x%x\n", SMRAMC_D_SMRAM(smramc));
}
void dump_bdsm_register(void) {
    phys_addr_t base_data_of_stolen_memory = 0;
    int bdsm = get_dram_register(DRAM_REGISTER_BDSM);
    if (bdsm < 0)
    {
        printk(KERN_INFO "FAILED to get bdsm register\n");
        return;
    }
    printk(KERN_INFO "BDSM register: 0x%x\n", bdsm);
    // bits 31-20 is the address
    base_data_of_stolen_memory = (bdsm >> 20) << 20;
    printk(KERN_INFO "  address: 0x%llx\n", base_data_of_stolen_memory);
    printk(KERN_INFO "  locked: %d\n", bdsm & 1);
}
void dump_bgsm_register(void) {
    phys_addr_t base_of_gtt_stolen_memory = 0;
    int bgsm = get_dram_register(DRAM_REGISTER_BGSM);
    if (bgsm < 0)
    {
        printk(KERN_INFO "FAILED to get bgsm register\n");
        return;
    }
    printk(KERN_INFO "BGSM register: 0x%x\n", bgsm);
    // bits 31-20 is the address
    base_of_gtt_stolen_memory = (bgsm >> 20) << 20;
    printk(KERN_INFO "  address: 0x%llx\n", base_of_gtt_stolen_memory);
    printk(KERN_INFO "  locked: %d\n", bgsm & 1);
}
void dump_tsegm_register(void) {
    phys_addr_t tsegm_addr = 0;
    int tsegm = get_dram_register(DRAM_REGISTER_TSEGMB);
    if (tsegm < 0)
    {
        printk(KERN_INFO "FAILED to get tsegm register\n");
        return;
    }
    printk(KERN_INFO "TSEGM register: 0x%x\n", tsegm);
    // bits 31-20 is the address
    tsegm_addr = (tsegm >> 20) << 20;
    printk(KERN_INFO "  address: 0x%llx\n", tsegm_addr);
    printk(KERN_INFO "  locked: %d\n", tsegm & 1);
}