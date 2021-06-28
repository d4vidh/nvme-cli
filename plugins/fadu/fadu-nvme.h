// clang-format off

#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/fadu/fadu-nvme

#if !defined(FADU_NVME) || defined(CMD_HEADER_MULTI_READ)
#define FADU_NVME

#include "cmd.h"

PLUGIN(NAME("fadu", "Fadu vendor specific extensions"),
	COMMAND_LIST(
		//ENTRY("fadu-smart-log", "Retrieve FADU SMART Log", get_fadu_smart_log) //FADU_LOG_VENDOR_SMART  F0
		ENTRY("vs-smart-add-log", "Retrieve SMART Information Extended Log", get_smart_add_log) // FADU_LOG_CLOUD_SMART C0
		ENTRY("vs-internal-log", "Retrieve FW Internal Log", get_internal_log)
		ENTRY("vs-fw-activate-history", "Retrieve FW Activation History", get_fw_activate_history) //FADU_LOG_FW_ACTIVATE_HISTORY  C2
		ENTRY("vs-drive-info", "Retrieve Drive Info", get_drive_info) // FADU_VUC_SUBOPCODE_VS_DRIVE_INFO  0x00080101
		ENTRY("log-page-directory", "Retrieve Log Page Directory", get_log_page_directory) // FADU_VUC_SUBOPCODE_LOG_PAGE_DIR 0x00080901
		ENTRY("clear-pcie-correctable-errors", "Clear PCIe Correctable Error Counters", clear_pcie_correctable_errors) //FADU_FEAT_CLEAR_PCIE_CORR_ERRORS C3
		ENTRY("clear-fw-activate-history", "Clear FW Update History", clear_fw_activate_history) // FADU_FEAT_CLEAR_FW_UPDATE_HISTORY C1
		//ENTRY("vs-telemetry-controller-option", "Control Controller-initiated Telemetry", control_telemetry_ctrl_option) // FADU_VUC_SUBOPCODE_SET_TELEMETRY_MODE C4
		ENTRY("cloud-ssd-plugin-version", "Show Cloud SSD Plugin Version", cloud_ssd_plugin_version) //0xC0
	)
);

#endif

#include "define_cmd.h"