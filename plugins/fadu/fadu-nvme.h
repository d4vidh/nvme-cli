// clang-format off

#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/fadu/fadu-nvme

#if !defined(FADU_NVME) || defined(CMD_HEADER_MULTI_READ)
#define FADU_NVME

#include "cmd.h"

PLUGIN(NAME("fadu", "Fadu vendor specific extensions"),
	COMMAND_LIST(
		ENTRY("vs-smart-add-log", "Retrieve SMART Information Extended Log", get_smart_add_log)
		ENTRY("vs-internal-log", "Retrieve FW Internal Log", get_internal_log)
		ENTRY("vs-fw-activate-history", "Retrieve FW Activation History", get_fw_activate_history)		
		ENTRY("clear-pcie-correctable-errors", "Clear PCIe Correctable Error Counters", clear_pcie_correctable_errors) //FADU_FEAT_CLEAR_PCIE_CORR_ERRORS C3
		ENTRY("clear-fw-activate-history", "Clear FW Update History", clear_fw_activate_history) // FADU_FEAT_CLEAR_FW_UPDATE_HISTORY C1		
		ENTRY("cloud-ssd-plugin-version", "Show Cloud SSD Plugin Version", cloud_ssd_plugin_version) //0xC0
	)
);

#endif

#include "define_cmd.h"