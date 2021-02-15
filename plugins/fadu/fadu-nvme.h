// clang-format off

#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/fadu/fadu-nvme

#if !defined(FADU_NVME) || defined(CMD_HEADER_MULTI_READ)
#define FADU_NVME

#include "cmd.h"

PLUGIN(NAME("fadu", "Fadu vendor specific extensions"),
	COMMAND_LIST(
		ENTRY("fadu-smart-log", "Retrieve FADU SMART Log", get_fadu_smart_log)
		ENTRY("vs-smart-add-log", "Retrieve SMART Information Extended Log", get_smart_add_log)
		ENTRY("vs-internal-log", "Retrieve FW Internal Log", get_internal_log)
		ENTRY("vs-fw-activate-history", "Retrieve FW Activation History", get_fw_activate_history)
		ENTRY("vs-drive-info", "Retrieve Drive Info", get_drive_info)
		ENTRY("log-page-directory", "Retrieve Log Page Directory", get_log_page_directory)
		ENTRY("clear-pcie-correctable-errors", "Clear PCIe Correctable Error Counters", clear_pcie_correctable_errors)
		ENTRY("clear-fw-activate-history", "Clear FW Update History", clear_fw_activate_history)
		ENTRY("vs-telemetry-controller-option", "Control Controller-initiated Telemetry", control_telemetry_ctrl_option)
		ENTRY("cloud-ssd-plugin-version", "Show Cloud SSD Plugin Version", cloud_ssd_plugin_version)
	)
);

#endif

#include "define_cmd.h"