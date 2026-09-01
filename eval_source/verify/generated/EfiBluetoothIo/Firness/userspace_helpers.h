#include "userspace_types.h"

typedef struct {
	SMM_CORE_PRIVATE_DATA *core;
	void *comm_buff;
	u64 comm_buff_phys_addr;
} smm_data_t;

int smm_enter_context(smm_data_t*);
void smm_leave_context(smm_data_t*);
void smm_call_smi(smm_data_t *smm_data, EFI_GUID *CommGuid, void *data, size_t size);
void smm_call_smi_data(smm_data_t *smm_data, EFI_GUID *CommGuid, u8 port_data, void *data, size_t size);
void smm_call_smi_data_cmd(smm_data_t *smm_data, EFI_GUID *CommGuid, u8 port_data, u8 port_cmd, void *data, size_t size);
