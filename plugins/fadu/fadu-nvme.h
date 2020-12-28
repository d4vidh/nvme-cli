#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/fadu/fadu-nvme

#if !defined(FADU_NVME) || defined(CMD_HEADER_MULTI_READ)
#define FADU_NVME

#include "cmd.h"

PLUGIN(NAME("fadu", "Fadu vendor specific extensions"),
    COMMAND_LIST(
        ENTRY("vs-smart-add-log", "Retrieve SMART Information Extended Log", fadu_vs_smart_add_log)
        ENTRY("vs-internal-log", "Retrieve FW Internal Log", fadu_vs_internal_log)
        ENTRY("vs-fw-activate-history", "Retrieve FW Activation History", fadu_vs_fw_activate_history)
        ENTRY("vs-drive-info", "Retrieve Drive Info", fadu_vs_drive_info)
        ENTRY("clear-pcie-correctable-errors", "Clear PCIe Correctable Error Counters", fadu_clear_pcie_correctable_errors)
        ENTRY("clear-fw-activate-history", "Clear FW Update History", fadu_clear_fw_activate_history)
        ENTRY("log-page-directory", "Retrieve Log Page Directory", fadu_log_page_directory)
        ENTRY("cloud-ssd-plugin-version", "Show Cloud SSD Plugin Version", fadu_cloud_ssd_plugin_version)
        ENTRY("vs-telemetry-controller-option", "Retrieve FW Internal Log", fadu_telemetry_controller_option)
    )
);

#endif

#include "define_cmd.h"