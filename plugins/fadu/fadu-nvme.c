#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "nvme.h"
#include "nvme-ioctl.h"
#include "nvme-print.h"
#include "nvme-status.h"
#include "plugin.h"
#include "json.h"

#define CREATE_CMD
#include "fadu-nvme.h"

enum {
	FADU_NVME_ADMIN_VUC_OPCODE = 0xC4,
};

enum {
	FADU_LOG_CLOUD_SMART = 0xC0,
	FADU_LOG_ERROR_RECOVERY = 0xC1,
	FADU_LOG_FW_ACTIVATE_HISTORY = 0xC2,
	FADU_LOG_VENDOR_SMART = 0xF0,
};

enum {
	FADU_FEAT_CLEAR_FW_UPDATE_HISTORY = 0xC1,
	FADU_FEAT_CLEAR_PCIE_CORR_ERRORS = 0xC3,
};

enum {
	FADU_VUC_SUBOPCODE_VS_DRIVE_INFO = 0x00080101,
	FADU_VUC_SUBOPCODE_LOG_PAGE_DIR = 0x00080901,
	FADU_VUC_SUBOPCODE_GET_TELEMETRY_MODE = 0x000C0101,
	FADU_VUC_SUBOPCODE_SET_TELEMETRY_MODE = 0x000C0000,
};

enum {
	DRV_LOG_PAGE_START = 1,
	DRV_LOG_PAGE_END = 65535,
	DRV_LOG_PAGE_SCHEME_VERSION = 10,
	DRV_LOG_PAGE_VERSION = 11,
	DRV_FIRMWARE_VERSION = 12,
	DRV_UNEXPECTED_POWER_OFF_COUNT = 20,
	DRV_TOTAL_GROWN_BAD_BLOCKS = 21,
	DRV_TOTAL_GROWN_BAD_BLOCKS_HIGHEST_DIE = 22,
	DRV_SMART_CRITICAL_EVENT_COUNT = 23,
	DRV_SMART_STATUS = 24,
	DRV_AVAILABLE_SPARE_BLOCKS = 25,
	DRV_AVAILABLE_SPARE_THRESHOLD = 26,
	DRV_MAXIMUM_POSSIBLE_SPARE_BLOCKS = 27,
	DRV_AVAILABLE_SPARE_BLOCKS_NORMALIZED = 28,
	DRV_TOTAL_RAW_READ_ERRORS = 29,
	DRV_TOTAL_READ_ERRORS = 30,
	DRV_TOTAL_READ_ERRORS_CORRECTABLE = 31,
	DRV_TOTAL_READ_ERRORS_UNCORRECTABLE = 32,
	DRV_TOTAL_READS_REQUIRING_HEROIC_RECOVERY = 33,
	DRV_TOTAL_READ_ERRORS_FROM_HOST_REQUESTS = 34,
	DRV_TOTAL_INTERNAL_READ_ERRORS = 35,
	DRV_TOTAL_ERASE_ERRORS = 36,
	DRV_TOTAL_PROGRAM_ERORS = 37,
	DRV_POWER_ON_HOUR_COUNT = 38,
	DRV_POWER_CYCLE_COUNT = 39,
	DRV_TLC_AVERAGE_PE_CYCLES = 40,
	DRV_TLC_MAXIMUM_PE_CYCLES = 41,
	DRV_TLC_MINIMUM_PE_CYCLES = 42,
	DRV_SLC_AVERAGE_PE_CYCLES = 43,
	DRV_SLC_MAXIMUM_PE_CYCLES = 44,
	DRV_SLC_MINIMUM_PE_CYCLES = 45,
	DRV_CUSTOMER_SLC_BUFFER_SIZE_GB = 46,
	DRV_NORMALIZED_MEDIA_WEAR = 47,
	DRV_NORMALIZED_HOST_WEAR = 48,
	DRV_HOST_GB_WRITTEN = 49,
	DRV_HOST_GB_READ = 50,
	DRV_MEDIA_GB_WRITTEN = 51,
	DRV_MEDIA_GB_READ = 52,
	DRV_HOST_FLUSHES_REQUESTED = 53,
	DRV_TOTAL_BLOCKS_COPIED_DUE_TO_READ_DISTURB = 54,
	DRV_TOTAL_TRIM_COMMANDS_REQUESTED = 55,
	DRV_TOTAL_4K_TRIMS_EXECUTED = 56,
	DRV_TOTAL_TRIM_COMMANDS_UNDER_PARTITION = 57,
	DRV_TOTAL_UNITS_OF_DATA_IN_REPLAY = 58,
	DRV_TLC_WRITE_AMPLIFICATION = 59,
	DRV_SLC_WRITE_AMPLIFICATION = 60,
	DRV_TOTAL_THROTTLING_LEVELS = 61,
	DRV_THROTTLING_ENTRY_COUNT_PER_LEVEL = 62,
	DRV_FIRST_THROTTLE_TEMP_THRESHOLD = 63,
	DRV_SHUTDOWN_TEMP = 64,
	DRV_NUMBER_OF_TEMP_SENSORS = 65,
	DRV_TEMP_SENSOR_0_CURRENT_TEMP = 66,
	DRV_TEMP_SENSOR_0_MINIMUM_TEMP = 67,
	DRV_TEMP_SENSOR_0_MAXIMUM_TEMP = 68,
	DRV_TEMP_SENSOR_1_CURRENT_TEMP = 69,
	DRV_TEMP_SENSOR_1_MINIMUM_TEMP = 70,
	DRV_TEMP_SENSOR_1_MAXIMUM_TEMP = 71,
	DRV_TEMP_SENSOR_2_CURRENT_TEMP = 72,
	DRV_TEMP_SENSOR_2_MINIMUM_TEMP = 73,
	DRV_TEMP_SENSOR_2_MAXIMUM_TEMP = 74,
	DRV_TEMP_SENSOR_3_CURRENT_TEMP = 75,
	DRV_TEMP_SENSOR_3_MINIMUM_TEMP = 76,
	DRV_TEMP_SENSOR_3_MAXIMUM_TEMP = 77,
	DRV_FRONT_END_LINK_DOWN_COUNTS = 78,
	DRV_FRONT_END_LINK_UP_COUNTS = 79,
	DRV_FRONT_END_CC_ENABLE_COUNTS = 80,
	DRV_FRONT_END_CC_DISABLE_COUNTS = 81,
	DRV_TIME_WAITING_FOR_CC_ENABLE = 82,
};

enum {
	NS_LOG_PAGE_START = 1,
	NS_LOG_PAGE_END = 65535,
	NS_HOST_GB_WRITTEN = 20,
	NS_HOST_GB_READ = 21,
	NS_HOST_FLUSHES_REQUESTED = 24,
	NS_TOTAL_TRIM_COMMANDS_REQUESTED = 26,
	NS_TOTAL_TRIM_COMMANDS_UNDER_PARTITION = 27,
};

#define MAX_FADU_SMART_LOG_LENGTH 4096

struct fadu_smart_log {
	__u8 raw[MAX_FADU_SMART_LOG_LENGTH];
};

struct ocp_bad_nand_block_count {
	__u64 raw : 48;
	__u16 normalized : 16;
};

struct ocp_e2e_correction_count {
	__u32 corrected;
	__u32 detected;
};

struct ocp_user_data_erase_count {
	__u32 maximum;
	__u32 minimum;
};

struct ocp_thermal_status {
	__u8 num_events;
	__u8 current_status;
};

struct ocp_cloud_smart_log {
	__u8 physical_media_units_written[16];
	__u8 physical_media_units_read[16];
	struct ocp_bad_nand_block_count bad_user_nand_blocks;
	struct ocp_bad_nand_block_count bad_system_nand_blocks;
	__u64 xor_recovery_count;
	__u64 uncorrectable_read_error_count;
	__u64 soft_ecc_error_count;
	struct ocp_e2e_correction_count e2e_correction_counts;
	__u8 system_data_percent_used;
	__u64 refresh_counts : 56;
	struct ocp_user_data_erase_count user_data_erase_counts;
	struct ocp_thermal_status thermal_status;
	__u8 rsvd98[6];
	__u64 pcie_correctable_error_count;
	__u32 incomplete_shutdowns;
	__u8 rsvd116[4];
	__u8 percent_free_blocks;
	__u8 rsvd121[7];
	__u16 capacitor_health;
	__u8 rsvd130[6];
	__u64 unaligned_io;
	__u64 security_version_number;
	__u64 nuse;
	__u8 plp_start_count[16];
	__u8 endurance_estimate[16];
	__u8 rsvd192[302];
	__u16 log_page_version;
	__u8 log_page_guid[16];
};

struct __attribute__((packed)) ocp_fw_act_history_entry {
	__u8 version;
	__u8 length;
	__u8 rsvd2[2];
	__u16 counter;
	__u64 timestamp;
	__u8 rsvd14[8];
	__u64 power_cycle;
	__u8 prev_fw[8];
	__u8 new_fw[8];
	__u8 slot;
	__u8 ca_type;
	__u16 result;
	__u8 rsvd50[14];
};

struct __attribute__((packed)) ocp_fw_act_history {
	__u8 log_id;
	__u8 rsvd1[3];
	__u32 num_entries;
	struct ocp_fw_act_history_entry entries[20];
	__u8 rsvd1288[2790];
	__u16 log_page_version;
	__u8 log_page_guid[16];
};

struct ocp_drive_info {
	__u32 hw_revision;
	__u32 ftl_unit_size;
};

struct ocp_log_page_directory {
	__u32 num_log_ids;
	__u8 rsvd4[12];
	__u8 log_ids[256];
	__u8 rsvd272[240];
};

static const int plugin_version_major = 1;
static const int plugin_version_minor = 0;

static const char *raw = "output in binary format";

static long double le_to_float(__u8 *data, int byte_len)
{
	long double result = 0;
	int i;

	for (i = 0; i < byte_len; i++) {
		result *= 256;
		result += data[15 - i];
	}

	return result;
}

static long double be_to_float(__u8 *data, int byte_len)
{
	long double result = 0;
	int i;

	for (i = 0; i < byte_len; i++) {
		result *= 256;
		result += data[i];
	}

	return result;
}

static __u64 be_to_int(__u8 *data, int byte_len)
{
	__u64 result = 0;
	int i;

	for (i = 0; i < byte_len; i++) {
		result <<= 8;
		result += data[i];
	}

	return result;
}

static const char *stringify_arg(const char *const *strings, size_t array_size, size_t idx)
{
	if (idx < array_size && strings[idx])
		return strings[idx];
	return "unrecognized";
}

static unsigned int get_num_dwords(unsigned int byte_len)
{
	unsigned int num_dwords;

	num_dwords = byte_len / 4;
	if (byte_len % 4 != 0)
		num_dwords += 1;

	return num_dwords;
}

static bool is_fadu_smart_log_string_attr(__u64 type_id)
{
	switch (type_id) {
	case DRV_LOG_PAGE_SCHEME_VERSION:
	case DRV_LOG_PAGE_VERSION:
	case DRV_FIRMWARE_VERSION:
		return true;
	default:
		return false;
	}
}

static const char *const fadu_smart_log_drv_attrs_json[] = {
	[DRV_LOG_PAGE_SCHEME_VERSION] = "log_page_scheme_version",
	[DRV_LOG_PAGE_VERSION] = "log_page_version",
	[DRV_FIRMWARE_VERSION] = "firmware_version",
	[DRV_UNEXPECTED_POWER_OFF_COUNT] = "unexpected_power_off_count",
	[DRV_TOTAL_GROWN_BAD_BLOCKS] = "total_grown_bad_blocks",
	[DRV_TOTAL_GROWN_BAD_BLOCKS_HIGHEST_DIE] = "total_grown_bad_blocks_highest_die",
	[DRV_SMART_CRITICAL_EVENT_COUNT] = "smart_critical_event_count",
	[DRV_SMART_STATUS] = "smart_status",
	[DRV_AVAILABLE_SPARE_BLOCKS] = "available_spare_blocks",
	[DRV_AVAILABLE_SPARE_THRESHOLD] = "available_spare_threshold",
	[DRV_MAXIMUM_POSSIBLE_SPARE_BLOCKS] = "maximum_possible_spare_blocks",
	[DRV_AVAILABLE_SPARE_BLOCKS_NORMALIZED] = "available_spare_blocks_normalized",
	[DRV_TOTAL_RAW_READ_ERRORS] = "total_raw_read_errors",
	[DRV_TOTAL_READ_ERRORS] = "total_read_errors",
	[DRV_TOTAL_READ_ERRORS_CORRECTABLE] = "total_read_errors_correctable",
	[DRV_TOTAL_READ_ERRORS_UNCORRECTABLE] = "total_read_errors_uncorrectable",
	[DRV_TOTAL_READS_REQUIRING_HEROIC_RECOVERY] = "total_reads_requiring_heroic_recovery",
	[DRV_TOTAL_READ_ERRORS_FROM_HOST_REQUESTS] = "total_read_errors_from_host_requests",
	[DRV_TOTAL_INTERNAL_READ_ERRORS] = "total_internal_read_errors",
	[DRV_TOTAL_ERASE_ERRORS] = "total_erase_errors",
	[DRV_TOTAL_PROGRAM_ERORS] = "total_program_errors",
	[DRV_POWER_ON_HOUR_COUNT] = "power_on_hour_count",
	[DRV_POWER_CYCLE_COUNT] = "power_cycle_count",
	[DRV_TLC_AVERAGE_PE_CYCLES] = "tlc_average_pe_cycles",
	[DRV_TLC_MAXIMUM_PE_CYCLES] = "tlc_maximum_pe_cycles",
	[DRV_TLC_MINIMUM_PE_CYCLES] = "tlc_minimum_pe_cycles",
	[DRV_SLC_AVERAGE_PE_CYCLES] = "slc_average_pe_cycles",
	[DRV_SLC_MAXIMUM_PE_CYCLES] = "slc_maximum_pe_cycles",
	[DRV_SLC_MINIMUM_PE_CYCLES] = "slc_minimum_pe_cycles",
	[DRV_CUSTOMER_SLC_BUFFER_SIZE_GB] = "customer_slc_buffer_size_gb",
	[DRV_NORMALIZED_MEDIA_WEAR] = "normalized_media_wear",
	[DRV_NORMALIZED_HOST_WEAR] = "normalized_host_wear",
	[DRV_HOST_GB_WRITTEN] = "host_gb_written",
	[DRV_HOST_GB_READ] = "host_gb_read",
	[DRV_MEDIA_GB_WRITTEN] = "media_gb_written",
	[DRV_MEDIA_GB_READ] = "media_gb_read",
	[DRV_HOST_FLUSHES_REQUESTED] = "host_flushes_requested",
	[DRV_TOTAL_BLOCKS_COPIED_DUE_TO_READ_DISTURB] = "total_blocks_copied_due_to_read_disturb",
	[DRV_TOTAL_TRIM_COMMANDS_REQUESTED] = "total_trim_commands_requested",
	[DRV_TOTAL_4K_TRIMS_EXECUTED] = "total_4k_trims_executed",
	[DRV_TOTAL_TRIM_COMMANDS_UNDER_PARTITION] = "total_trim_commands_under_partition",
	[DRV_TOTAL_UNITS_OF_DATA_IN_REPLAY] = "total_units_of_data_in_replay",
	[DRV_TLC_WRITE_AMPLIFICATION] = "tlc_write_amplification",
	[DRV_SLC_WRITE_AMPLIFICATION] = "slc_write_amplification",
	[DRV_TOTAL_THROTTLING_LEVELS] = "total_throttling_levels",
	[DRV_THROTTLING_ENTRY_COUNT_PER_LEVEL] = "throttling_entry_counts",
	[DRV_FIRST_THROTTLE_TEMP_THRESHOLD] = "first_throttle_temp_threshold",
	[DRV_SHUTDOWN_TEMP] = "shutdown_temp",
	[DRV_NUMBER_OF_TEMP_SENSORS] = "number_of_temp_sensors",
	[DRV_TEMP_SENSOR_0_CURRENT_TEMP] = "temp_sensor_0_current_temp",
	[DRV_TEMP_SENSOR_0_MINIMUM_TEMP] = "temp_sensor_0_minimum_temp",
	[DRV_TEMP_SENSOR_0_MAXIMUM_TEMP] = "temp_sensor_0_maximum_temp",
	[DRV_TEMP_SENSOR_1_CURRENT_TEMP] = "temp_sensor_1_current_temp",
	[DRV_TEMP_SENSOR_1_MINIMUM_TEMP] = "temp_sensor_1_minimum_temp",
	[DRV_TEMP_SENSOR_1_MAXIMUM_TEMP] = "temp_sensor_1_maximum_temp",
	[DRV_TEMP_SENSOR_2_CURRENT_TEMP] = "temp_sensor_2_current_temp",
	[DRV_TEMP_SENSOR_2_MINIMUM_TEMP] = "temp_sensor_2_minimum_temp",
	[DRV_TEMP_SENSOR_2_MAXIMUM_TEMP] = "temp_sensor_2_maximum_temp",
	[DRV_TEMP_SENSOR_3_CURRENT_TEMP] = "temp_sensor_3_current_temp",
	[DRV_TEMP_SENSOR_3_MINIMUM_TEMP] = "temp_sensor_3_minimum_temp",
	[DRV_TEMP_SENSOR_3_MAXIMUM_TEMP] = "temp_sensor_3_maximum_temp",
	[DRV_FRONT_END_LINK_DOWN_COUNTS] = "front_end_link_down_counts",
	[DRV_FRONT_END_LINK_UP_COUNTS] = "front_end_link_up_counts",
	[DRV_FRONT_END_CC_ENABLE_COUNTS] = "front_end_cc_enable_counts",
	[DRV_FRONT_END_CC_DISABLE_COUNTS] = "front_end_cc_disable_counts",
	[DRV_TIME_WAITING_FOR_CC_ENABLE] = "time_waiting_for_cc_enable",
};

static const char *stringify_fadu_smart_log_drv_attr_json(__u64 type_id)
{
	return stringify_arg(fadu_smart_log_drv_attrs_json, ARRAY_SIZE(fadu_smart_log_drv_attrs_json), type_id);
}

static void show_fadu_smart_log_drv_json(struct fadu_smart_log *log)
{
	struct json_object *root;
	struct json_object *throttling_entry_counts;
	char buf[16];
	int offset = 0;
	__u64 type_id, length, value, num_throttling_levels = 0;
	const char *name;
	int throttling_entry_length, i;

	root = json_create_object();

	while (offset < MAX_FADU_SMART_LOG_LENGTH) {
		type_id = be_to_int(log->raw + offset, 2);
		offset += 2;

		length = be_to_int(log->raw + offset, 2);
		offset += 2;

		if (type_id == NS_LOG_PAGE_START)
			continue;
		else if (type_id == NS_LOG_PAGE_END)
			break;

		name = stringify_fadu_smart_log_drv_attr_json(type_id);
		if (is_fadu_smart_log_string_attr(type_id)) {
			json_object_add_value_string(root, name, log->raw + offset);
		} else if (type_id == DRV_THROTTLING_ENTRY_COUNT_PER_LEVEL) {
			throttling_entry_counts = json_create_object();
			throttling_entry_length = length / num_throttling_levels;
			for (i = 0; i < num_throttling_levels; i++) {
				memset(buf, 0, sizeof(char) * 16);
				sprintf(buf, "L%d", i);
				value = be_to_int(log->raw + offset + (i * throttling_entry_length),
						  throttling_entry_length);
				json_object_add_value_uint(throttling_entry_counts, buf, value);
			}
			json_object_add_value_object(root, "throttling_entry_counts", throttling_entry_counts);
		} else if (length > 8) {
			json_object_add_value_float(root, name, be_to_float(log->raw + offset, length));
		} else {
			value = be_to_int(log->raw + offset, length);
			json_object_add_value_uint(root, name, value);
			if (type_id == DRV_TOTAL_THROTTLING_LEVELS)
				num_throttling_levels = value;
		}

		offset += length;
	}

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static const char *const fadu_smart_log_drv_attrs_normal[] = {
	[DRV_LOG_PAGE_SCHEME_VERSION] = "Log Page Scheme Version",
	[DRV_LOG_PAGE_VERSION] = "Log Page Version",
	[DRV_FIRMWARE_VERSION] = "Firmware Version",
	[DRV_UNEXPECTED_POWER_OFF_COUNT] = "Unexpected Power Off Count",
	[DRV_TOTAL_GROWN_BAD_BLOCKS] = "Total Grown Bad Blocks",
	[DRV_TOTAL_GROWN_BAD_BLOCKS_HIGHEST_DIE] = "Total Grown Bad Blocks Highest Die",
	[DRV_SMART_CRITICAL_EVENT_COUNT] = "SMART Critical Event Count",
	[DRV_SMART_STATUS] = "SMART Status",
	[DRV_AVAILABLE_SPARE_BLOCKS] = "Available Spare Blocks",
	[DRV_AVAILABLE_SPARE_THRESHOLD] = "Available Spare Threshold",
	[DRV_MAXIMUM_POSSIBLE_SPARE_BLOCKS] = "Maximum Possible Spare Blocks",
	[DRV_AVAILABLE_SPARE_BLOCKS_NORMALIZED] = "Available Spare Blocks Normalized",
	[DRV_TOTAL_RAW_READ_ERRORS] = "Total Raw Read Errors",
	[DRV_TOTAL_READ_ERRORS] = "Total Read Errors",
	[DRV_TOTAL_READ_ERRORS_CORRECTABLE] = "Total Read Errors Correctable",
	[DRV_TOTAL_READ_ERRORS_UNCORRECTABLE] = "Total Read Errors Uncorrectable",
	[DRV_TOTAL_READS_REQUIRING_HEROIC_RECOVERY] = "Total Reads Requiring Heroic Recovery",
	[DRV_TOTAL_READ_ERRORS_FROM_HOST_REQUESTS] = "Total Read Errors From Host Requests",
	[DRV_TOTAL_INTERNAL_READ_ERRORS] = "Total Internal Read Errors",
	[DRV_TOTAL_ERASE_ERRORS] = "Total Erase Errors",
	[DRV_TOTAL_PROGRAM_ERORS] = "Total Program Errors",
	[DRV_POWER_ON_HOUR_COUNT] = "Power On Hour Count",
	[DRV_POWER_CYCLE_COUNT] = "Power Cycle Count",
	[DRV_TLC_AVERAGE_PE_CYCLES] = "TLC Average PE Cycles",
	[DRV_TLC_MAXIMUM_PE_CYCLES] = "TLC Maximum PE Cycles",
	[DRV_TLC_MINIMUM_PE_CYCLES] = "TLC Minimum PE Cycles",
	[DRV_SLC_AVERAGE_PE_CYCLES] = "SLC Average PE Cycles",
	[DRV_SLC_MAXIMUM_PE_CYCLES] = "SLC Maximum PE Cycles",
	[DRV_SLC_MINIMUM_PE_CYCLES] = "SLC Minimum PE Cycles",
	[DRV_CUSTOMER_SLC_BUFFER_SIZE_GB] = "Customer SLC Buffer Size GB",
	[DRV_NORMALIZED_MEDIA_WEAR] = "Normalized Media Wear",
	[DRV_NORMALIZED_HOST_WEAR] = "Normalized Host Wear",
	[DRV_HOST_GB_WRITTEN] = "Host GB Written",
	[DRV_HOST_GB_READ] = "Host GB Read",
	[DRV_MEDIA_GB_WRITTEN] = "Media GB Written",
	[DRV_MEDIA_GB_READ] = "Media GB Read",
	[DRV_HOST_FLUSHES_REQUESTED] = "Host Flushes Requested",
	[DRV_TOTAL_BLOCKS_COPIED_DUE_TO_READ_DISTURB] = "Total Blocks Copied Due To Read Disturb",
	[DRV_TOTAL_TRIM_COMMANDS_REQUESTED] = "Total Trim Commands Requested",
	[DRV_TOTAL_4K_TRIMS_EXECUTED] = "Total 4K Trims Executed",
	[DRV_TOTAL_TRIM_COMMANDS_UNDER_PARTITION] = "Total Trim Commands Under Partition",
	[DRV_TOTAL_UNITS_OF_DATA_IN_REPLAY] = "Total Units Of Data In Replay",
	[DRV_TLC_WRITE_AMPLIFICATION] = "TLC Write Amplification",
	[DRV_SLC_WRITE_AMPLIFICATION] = "SLC Write Amplification",
	[DRV_TOTAL_THROTTLING_LEVELS] = "Total Throttling Levels",
	[DRV_THROTTLING_ENTRY_COUNT_PER_LEVEL] = "Throttling Entry Count",
	[DRV_FIRST_THROTTLE_TEMP_THRESHOLD] = "First Throttle Temp Threshold",
	[DRV_SHUTDOWN_TEMP] = "Shutdown Temp",
	[DRV_NUMBER_OF_TEMP_SENSORS] = "Number Of Temp Sensors",
	[DRV_TEMP_SENSOR_0_CURRENT_TEMP] = "Temp Sensor 0 Current Temp",
	[DRV_TEMP_SENSOR_0_MINIMUM_TEMP] = "Temp Sensor 0 Minimum Temp",
	[DRV_TEMP_SENSOR_0_MAXIMUM_TEMP] = "Temp Sensor 0 Maximum Temp",
	[DRV_TEMP_SENSOR_1_CURRENT_TEMP] = "Temp Sensor 1 Current Temp",
	[DRV_TEMP_SENSOR_1_MINIMUM_TEMP] = "Temp Sensor 1 Minimum Temp",
	[DRV_TEMP_SENSOR_1_MAXIMUM_TEMP] = "Temp Sensor 1 Maximum Temp",
	[DRV_TEMP_SENSOR_2_CURRENT_TEMP] = "Temp Sensor 2 Current Temp",
	[DRV_TEMP_SENSOR_2_MINIMUM_TEMP] = "Temp Sensor 2 Minimum Temp",
	[DRV_TEMP_SENSOR_2_MAXIMUM_TEMP] = "Temp Sensor 2 Maximum Temp",
	[DRV_TEMP_SENSOR_3_CURRENT_TEMP] = "Temp Sensor 3 Current Temp",
	[DRV_TEMP_SENSOR_3_MINIMUM_TEMP] = "Temp Sensor 3 Minimum Temp",
	[DRV_TEMP_SENSOR_3_MAXIMUM_TEMP] = "Temp Sensor 3 Maximum Temp",
	[DRV_FRONT_END_LINK_DOWN_COUNTS] = "Front End Link Down Counts",
	[DRV_FRONT_END_LINK_UP_COUNTS] = "Front End Link Up Counts",
	[DRV_FRONT_END_CC_ENABLE_COUNTS] = "Front End CC_Enable Counts",
	[DRV_FRONT_END_CC_DISABLE_COUNTS] = "Front End CC_Disable Counts",
	[DRV_TIME_WAITING_FOR_CC_ENABLE] = "Time Waiting For CC_Enable",
};

static const char *stringify_fadu_smart_log_drv_attr_normal(__u64 type_id)
{
	return stringify_arg(fadu_smart_log_drv_attrs_normal, ARRAY_SIZE(fadu_smart_log_drv_attrs_normal), type_id);
}

static void show_fadu_smart_log_drv_normal(struct fadu_smart_log *log)
{
	int offset = 0;
	__u64 type_id, length, value, num_throttling_levels = 0;
	const char *name;
	int throttling_entry_length, i;

	while (offset < MAX_FADU_SMART_LOG_LENGTH) {
		type_id = be_to_int(log->raw + offset, 2);
		offset += 2;

		length = be_to_int(log->raw + offset, 2);
		offset += 2;

		if (type_id == NS_LOG_PAGE_START)
			continue;
		else if (type_id == NS_LOG_PAGE_END)
			break;

		name = stringify_fadu_smart_log_drv_attr_normal(type_id);
		if (is_fadu_smart_log_string_attr(type_id)) {
			printf("%-40s: %s\n", name, log->raw + offset);
		} else if (type_id == DRV_THROTTLING_ENTRY_COUNT_PER_LEVEL) {
			throttling_entry_length = length / num_throttling_levels;
			for (i = 0; i < num_throttling_levels; i++) {
				value = be_to_int(log->raw + offset + (i * throttling_entry_length),
						  throttling_entry_length);
				printf("%s (L%d)             : %lld\n", name, i, value);
			}
		} else if (length > 8) {
			printf("%-40s: %'.0Lf\n", name, be_to_float(log->raw + offset, length));
		} else {
			value = be_to_int(log->raw + offset, length);
			printf("%-40s: %lld\n", name, value);
			if (type_id == DRV_TOTAL_THROTTLING_LEVELS)
				num_throttling_levels = value;
		}

		offset += length;
	}

	printf("\n\n");
}

static const char *const fadu_smart_log_ns_attrs_json[] = {
	[NS_HOST_GB_WRITTEN] = "host_gb_written",
	[NS_HOST_GB_READ] = "host_gb_read",
	[NS_HOST_FLUSHES_REQUESTED] = "host_flushes_requested",
	[NS_TOTAL_TRIM_COMMANDS_REQUESTED] = "total_trim_commands_requested",
	[NS_TOTAL_TRIM_COMMANDS_UNDER_PARTITION] = "total_trim_commands_under_partition",
};

static const char *stringify_fadu_smart_log_ns_attr_json(__u64 type_id)
{
	return stringify_arg(fadu_smart_log_ns_attrs_json, ARRAY_SIZE(fadu_smart_log_ns_attrs_json), type_id);
}

static void show_fadu_smart_log_ns_json(struct fadu_smart_log *log)
{
	struct json_object *root;
	int offset = 0;
	__u64 type_id, length;
	const char *name;

	root = json_create_object();

	while (offset < MAX_FADU_SMART_LOG_LENGTH) {
		type_id = be_to_int(log->raw + offset, 2);
		offset += 2;

		length = be_to_int(log->raw + offset, 2);
		offset += 2;

		if (type_id == NS_LOG_PAGE_START)
			continue;
		else if (type_id == NS_LOG_PAGE_END)
			break;

		name = stringify_fadu_smart_log_ns_attr_json(type_id);
		if (length > 8)
			json_object_add_value_float(root, name, be_to_float(log->raw + offset, length));
		else
			json_object_add_value_uint(root, name, be_to_int(log->raw + offset, length));

		offset += length;
	}

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static const char *const fadu_smart_log_ns_attrs_normal[] = {
	[NS_HOST_GB_WRITTEN] = "Host GB Written",
	[NS_HOST_GB_READ] = "Host GB Read",
	[NS_HOST_FLUSHES_REQUESTED] = "Host Flushes Requested",
	[NS_TOTAL_TRIM_COMMANDS_REQUESTED] = "Total Trim Commands Requested",
	[NS_TOTAL_TRIM_COMMANDS_UNDER_PARTITION] = "Total Trim Commands Under Partition",
};

static const char *stringify_fadu_smart_log_ns_attr_normal(__u64 type_id)
{
	return stringify_arg(fadu_smart_log_ns_attrs_normal, ARRAY_SIZE(fadu_smart_log_ns_attrs_normal), type_id);
}

static void show_fadu_smart_log_ns_normal(struct fadu_smart_log *log)
{
	int offset = 0;
	__u64 type_id, length;

	while (offset < MAX_FADU_SMART_LOG_LENGTH) {
		type_id = be_to_int(log->raw + offset, 2);
		offset += 2;

		length = be_to_int(log->raw + offset, 2);
		offset += 2;

		if (type_id == NS_LOG_PAGE_START)
			continue;
		else if (type_id == NS_LOG_PAGE_END)
			break;

		printf("%-35s : ", stringify_fadu_smart_log_ns_attr_normal(type_id));
		if (length > 8)
			printf("%'.0Lf\n", be_to_float(log->raw + offset, length));
		else
			printf("%lld\n", be_to_int(log->raw + offset, length));

		offset += length;
	}

	printf("\n\n");
}

static void show_fadu_smart_log(struct fadu_smart_log *log, unsigned int nsid, enum nvme_print_flags flags)
{
	if (flags & BINARY) {
		return d_raw((unsigned char *)log, sizeof(*log));
	} else if (flags & JSON) {
		if (nsid == NVME_NSID_ALL)
			return show_fadu_smart_log_drv_json(log);
		else
			return show_fadu_smart_log_ns_json(log);
	}

	if (nsid == NVME_NSID_ALL)
		show_fadu_smart_log_drv_normal(log);
	else
		show_fadu_smart_log_ns_normal(log);
}

static int get_fadu_smart_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct fadu_smart_log log;
	const char *desc = "Retrieve FADU-specific SMART log.";
	const char *namespace = "(Optional) desired namespace";
	int flags, err, fd;

	struct config {
		__u32 namespace_id;
		char *output_format;
		int raw_binary;
	};

	struct config cfg = {
		.namespace_id = NVME_NSID_ALL,
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary", 'b', &cfg.raw_binary, raw),
		OPT_END(),
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0) {
		fprintf(stderr, "Invalid output format: %s\n", cfg.output_format);
		goto close_fd;
	}
	if (cfg.raw_binary)
		flags = BINARY;

	err = nvme_get_log(fd, cfg.namespace_id, FADU_LOG_VENDOR_SMART, false, sizeof(log), &log);
	if (!err)
		show_fadu_smart_log(&log, cfg.namespace_id, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("vs-smart-add-log");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static void stringify_log_page_guid(__u8 *guid, char *buf)
{
	char *ptr = buf;
	int i;

	memset(buf, 0, sizeof(char) * 19);

	ptr += sprintf(ptr, "0x");
	for (i = 0; i < 16; i++)
		ptr += sprintf(ptr, "%x", guid[15 - i]);
}

static const char *const cloud_smart_log_thermal_status[] = {
	[0x00] = "unthrottled",
	[0x01] = "first_level",
	[0x02] = "second_level",
	[0x03] = "third_level",
};

static const char *stringify_cloud_smart_log_thermal_status(__u8 status)
{
	return stringify_arg(cloud_smart_log_thermal_status, ARRAY_SIZE(cloud_smart_log_thermal_status), status);
}

static void show_cloud_smart_log_json(struct ocp_cloud_smart_log *log)
{
	struct json_object *root;
	struct json_object *bad_user_nand_blocks;
	struct json_object *bad_system_nand_blocks;
	struct json_object *e2e_correction_counts;
	struct json_object *user_data_erase_counts;
	struct json_object *thermal_status;
	char buf[2 * sizeof(log->log_page_guid) + 3];

	bad_user_nand_blocks = json_create_object();
	json_object_add_value_uint(bad_user_nand_blocks, "normalized",
				   le16_to_cpu(log->bad_user_nand_blocks.normalized));
	json_object_add_value_uint(bad_user_nand_blocks, "raw", le64_to_cpu(log->bad_user_nand_blocks.raw));

	bad_system_nand_blocks = json_create_object();
	json_object_add_value_uint(bad_system_nand_blocks, "normalized",
				   le16_to_cpu(log->bad_system_nand_blocks.normalized));
	json_object_add_value_uint(bad_system_nand_blocks, "raw", le64_to_cpu(log->bad_system_nand_blocks.raw));

	e2e_correction_counts = json_create_object();
	json_object_add_value_uint(e2e_correction_counts, "corrected",
				   le32_to_cpu(log->e2e_correction_counts.corrected));
	json_object_add_value_uint(e2e_correction_counts, "detected", le32_to_cpu(log->e2e_correction_counts.detected));

	user_data_erase_counts = json_create_object();
	json_object_add_value_uint(user_data_erase_counts, "minimum", le32_to_cpu(log->user_data_erase_counts.minimum));
	json_object_add_value_uint(user_data_erase_counts, "maximum", le32_to_cpu(log->user_data_erase_counts.maximum));

	thermal_status = json_create_object();
	json_object_add_value_string(thermal_status, "current_status",
				     stringify_cloud_smart_log_thermal_status(log->thermal_status.current_status));
	json_object_add_value_uint(thermal_status, "num_events", log->thermal_status.num_events);

	root = json_create_object();
	json_object_add_value_float(root, "physical_media_units_written",
				    le_to_float(log->physical_media_units_written, 16));
	json_object_add_value_float(root, "physical_media_units_read", le_to_float(log->physical_media_units_read, 16));
	json_object_add_value_object(root, "bad_user_nand_blocks", bad_user_nand_blocks);
	json_object_add_value_object(root, "bad_system_nand_blocks", bad_system_nand_blocks);
	json_object_add_value_uint(root, "xor_recovery_count", le64_to_cpu(log->xor_recovery_count));
	json_object_add_value_uint(root, "uncorrectable_read_error_count",
				   le64_to_cpu(log->uncorrectable_read_error_count));
	json_object_add_value_uint(root, "soft_ecc_error_count", le64_to_cpu(log->soft_ecc_error_count));
	json_object_add_value_object(root, "e2e_correction_counts", e2e_correction_counts);
	json_object_add_value_uint(root, "system_data_percent_used", log->system_data_percent_used);
	json_object_add_value_uint(root, "refresh_counts", le64_to_cpu(log->refresh_counts));
	json_object_add_value_object(root, "user_data_erase_counts", user_data_erase_counts);
	json_object_add_value_object(root, "thermal_status", thermal_status);
	json_object_add_value_uint(root, "pcie_correctable_error_count",
				   le64_to_cpu(log->pcie_correctable_error_count));
	json_object_add_value_uint(root, "incomplete_shutdowns", le32_to_cpu(log->incomplete_shutdowns));
	json_object_add_value_uint(root, "percent_free_blocks", log->percent_free_blocks);
	json_object_add_value_uint(root, "capacitor_health", le16_to_cpu(log->capacitor_health));
	json_object_add_value_uint(root, "unaligned_io", le64_to_cpu(log->unaligned_io));
	json_object_add_value_uint(root, "security_version_number", le64_to_cpu(log->security_version_number));
	json_object_add_value_uint(root, "nuse", le64_to_cpu(log->nuse));
	json_object_add_value_float(root, "plp_start_count", le_to_float(log->plp_start_count, 16));
	json_object_add_value_float(root, "endurance_estimate", le_to_float(log->endurance_estimate, 16));
	json_object_add_value_uint(root, "log_page_version", le16_to_cpu(log->log_page_version));
	stringify_log_page_guid(log->log_page_guid, buf);
	json_object_add_value_string(root, "log_page_guid", buf);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void show_cloud_smart_log_normal(struct ocp_cloud_smart_log *log)
{
	char buf[2 * sizeof(log->log_page_guid) + 3];

	printf("Smart Extended Log for NVME device:%s\n", devicename);
	printf("Physical Media Units Written                 : %'.0Lf\n",
	       le_to_float(log->physical_media_units_written, 16));
	printf("Physical Media Units Read                    : %'.0Lf\n",
	       le_to_float(log->physical_media_units_read, 16));
	printf("Bad User NAND Blocks (Normalized)            : %" PRIu16 "%%\n",
	       le16_to_cpu(log->bad_user_nand_blocks.normalized));
	printf("Bad User NAND Blocks (Raw)                   : %" PRIu64 "\n",
	       le64_to_cpu(log->bad_user_nand_blocks.raw));
	printf("Bad System NAND Blocks (Normalized)          : %" PRIu16 "%%\n",
	       le16_to_cpu(log->bad_system_nand_blocks.normalized));
	printf("Bad System NAND Blocks (Raw)                 : %" PRIu64 "\n",
	       le64_to_cpu(log->bad_system_nand_blocks.raw));
	printf("XOR Recovery Count                           : %" PRIu64 "\n", le64_to_cpu(log->xor_recovery_count));
	printf("Uncorrectable Read Error Count               : %" PRIu64 "\n",
	       le64_to_cpu(log->uncorrectable_read_error_count));
	printf("Soft ECC Error Count                         : %" PRIu64 "\n", le64_to_cpu(log->soft_ecc_error_count));
	printf("End to End Correction Counts (Corrected)     : %" PRIu32 "\n",
	       le32_to_cpu(log->e2e_correction_counts.corrected));
	printf("End to End Correction Counts (Detected)      : %" PRIu32 "\n",
	       le32_to_cpu(log->e2e_correction_counts.detected));
	printf("System Data %% Used                           : %" PRIu8 "%%\n", log->system_data_percent_used);
	printf("Refresh Counts                               : %" PRIu64 "\n", le64_to_cpu(log->refresh_counts));
	printf("User Data Erase Counts (Minimum)             : %" PRIu32 "\n",
	       le32_to_cpu(log->user_data_erase_counts.minimum));
	printf("User Data Erase Counts (Maximum)             : %" PRIu32 "\n",
	       le32_to_cpu(log->user_data_erase_counts.maximum));
	printf("Thermal Throttling Status (Current Status)   : %s\n",
	       stringify_cloud_smart_log_thermal_status(log->thermal_status.current_status));
	printf("Thermal Throttling Status (Number of Events) : %" PRIu8 "\n", log->thermal_status.num_events);
	printf("PCIe Correctable Error Count                 : %" PRIu64 "\n",
	       le64_to_cpu(log->pcie_correctable_error_count));
	printf("Incomplete Shutdowns                         : %" PRIu32 "\n", le32_to_cpu(log->incomplete_shutdowns));
	printf("%% Free Blocks                                : %" PRIu8 "%%\n", log->percent_free_blocks);
	printf("Capacitor Health                             : %" PRIu16 "%%\n", le16_to_cpu(log->capacitor_health));
	printf("Unaligned IO                                 : %" PRIu64 "\n", le64_to_cpu(log->unaligned_io));
	printf("Security Version Number                      : %" PRIu64 "\n",
	       le64_to_cpu(log->security_version_number));
	printf("NUSE                                         : %" PRIu64 "\n", le64_to_cpu(log->nuse));
	printf("PLP Start Count                              : %'.0Lf\n", le_to_float(log->plp_start_count, 16));
	printf("Endurance Estimate                           : %'.0Lf\n", le_to_float(log->endurance_estimate, 16));
	printf("Log Page Version                             : %" PRIu16 "\n", le16_to_cpu(log->log_page_version));
	stringify_log_page_guid(log->log_page_guid, buf);
	printf("Log Page GUID                                : %s\n", buf);
	printf("\n\n");
}

static void show_cloud_smart_log(struct ocp_cloud_smart_log *log, enum nvme_print_flags flags)
{
	if (flags & BINARY)
		return d_raw((unsigned char *)log, sizeof(*log));
	else if (flags & JSON)
		return show_cloud_smart_log_json(log);

	show_cloud_smart_log_normal(log);
}

static int get_smart_add_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct ocp_cloud_smart_log log;
	const char *desc = "Retrieve SMART Cloud Attributes log.";
	int flags, err, fd;
	char buf[2 * sizeof(log.log_page_guid) + 3];

	struct config {
		char *output_format;
		int raw_binary;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary", 'b', &cfg.raw_binary, raw),
		OPT_END(),
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0) {
		fprintf(stderr, "Invalid output format: %s\n", cfg.output_format);
		goto close_fd;
	}
	if (cfg.raw_binary)
		flags = BINARY;

	err = nvme_get_log(fd, NVME_NSID_ALL, FADU_LOG_CLOUD_SMART, false, sizeof(log), &log);
	if (!err) {
		stringify_log_page_guid(log.log_page_guid, buf);
		if (strcmp(buf, "0xafd514c97c6f4f9ca4f2bfea2810afc5"))
			fprintf(stderr, "Invalid GUID: %s\n", buf);
		else
			show_cloud_smart_log(&log, flags);
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		perror("vs-smart-add-log");
	}

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int create_log_file(char *file_path, __u8 *data, __u32 length)
{
	int err, fd;

	if (length == 0)
		return -EINVAL;

	err = fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (fd < 0) {
		fprintf(stderr, "Failed to open output file %s: %s!\n", file_path, strerror(errno));
		goto ret;
	}

	err = write(fd, data, length);
	if (err < 0) {
		fprintf(stderr, "Failed write: %s!\n", strerror(errno));
		goto close_fd;
	}

	err = fsync(fd);
	if (err < 0)
		fprintf(stderr, "Failed fsync: %s!\n", strerror(errno));

close_fd:
	close(fd);
ret:
	return err;
}

static int dump_internal_logs(int fd, char *dir_name, int verbose)
{
	char file_path[128];
	struct nvme_smart_log smart_log;
	struct ocp_cloud_smart_log cloud_smart_log;
	void *telemetry_log;
	const size_t bs = 512;
	struct nvme_telemetry_log_page_hdr *hdr;
	size_t full_size, offset = bs;
	int err, output;

	if (verbose)
		printf("Cloud SMART log...\n");

	err = nvme_get_log(fd, NVME_NSID_ALL, FADU_LOG_CLOUD_SMART, false, sizeof(cloud_smart_log), &cloud_smart_log);
	if (!err) {
		sprintf(file_path, "%s/cloud.bin", dir_name);
		err = create_log_file(file_path, (__u8 *)&cloud_smart_log, sizeof(cloud_smart_log));
	} else {
		fprintf(stderr, "Failed to dump Cloud SMART log!\n");
	}

	if (verbose)
		printf("NVMe SMART log...\n");

	err = nvme_smart_log(fd, NVME_NSID_ALL, &smart_log);
	if (!err) {
		sprintf(file_path, "%s/smart.bin", dir_name);
		err = create_log_file(file_path, (__u8 *)&smart_log, sizeof(smart_log));
	} else {
		fprintf(stderr, "Failed to dump NVMe SMART log!\n");
	}

	if (verbose)
		printf("NVMe Telemetry log...\n");

	hdr = malloc(bs);
	telemetry_log = malloc(bs);
	if (!hdr || !telemetry_log) {
		fprintf(stderr, "Failed to allocate %zu bytes for log: %s\n", bs, strerror(errno));
		err = -ENOMEM;
		goto free_mem;
	}
	memset(hdr, 0, bs);

	sprintf(file_path, "%s/telemetry.bin", dir_name);
	output = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (output < 0) {
		fprintf(stderr, "Failed to open output file %s: %s!\n", file_path, strerror(errno));
		err = output;
		goto free_mem;
	}

	err = nvme_get_telemetry_log(fd, hdr, 1, 0, bs, 0);
	if (err < 0)
		perror("get-telemetry-log");
	else if (err > 0) {
		nvme_show_status(err);
		fprintf(stderr, "Failed to acquire telemetry header %d!\n", err);
		goto close_output;
	}

	err = write(output, (void *)hdr, bs);
	if (err != bs) {
		fprintf(stderr, "Failed to flush all data to file!\n");
		goto close_output;
	}

	full_size = (le16_to_cpu(hdr->dalb3) * bs) + offset;

	while (offset != full_size) {
		err = nvme_get_telemetry_log(fd, telemetry_log, 0, 0, bs, offset);
		if (err < 0) {
			perror("get-telemetry-log");
			break;
		} else if (err > 0) {
			fprintf(stderr, "Failed to acquire full telemetry log!\n");
			nvme_show_status(err);
			break;
		}

		err = write(output, (void *)telemetry_log, bs);
		if (err != bs) {
			fprintf(stderr, "Failed to flush all data to file!\n");
			break;
		}
		err = 0;
		offset += bs;
	}

close_output:
	close(output);
free_mem:
	free(hdr);
	free(telemetry_log);

	return err;
}

static int get_internal_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Retrieve FW internal log.\n"
			   "Output file includes smart-log, vs-smart-add-log, and telemetry-log.";
	const char *fname = "File name to save without extension";
	const char *verbose = "Increase output verbosity";
	char file_path[128];
	char cmd_buf[256];
	int err, fd;

	struct config {
		char *file_name;
		int verbose;
	};

	struct config cfg = {
		.file_name = NULL,
		.verbose = 0,
	};

	OPT_ARGS(opts) = {
		OPT_FILE("output-file", 'o', &cfg.file_name, fname),
		OPT_FLAG("verbose", 'v', &cfg.verbose, verbose),
		OPT_END(),
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if (!cfg.file_name) {
		fprintf(stderr, "Please provide an output file!\n");
		err = -EINVAL;
		goto close_fd;
	}

	memset(file_path, 0, 64);
	sprintf(file_path, "%s.tar.gz", cfg.file_name);
	if (access(file_path, F_OK) != -1) {
		fprintf(stderr, "Output file already exists!\n");
		err = -EEXIST;
		goto close_fd;
	}

	if (cfg.verbose)
		printf("Creating temp directory...\n");

	err = mkdir(cfg.file_name, 0666);
	if (err) {
		fprintf(stderr, "Failed to create directory!\n");
		goto close_fd;
	}

	err = dump_internal_logs(fd, cfg.file_name, cfg.verbose);
	if (err < 0)
		perror("vs-internal-log");

	if (cfg.verbose)
		printf("Archiving...\n");

	sprintf(cmd_buf, "tar --remove-files -czf %s %s", file_path, cfg.file_name);
	err = system(cmd_buf);
	if (err) {
		fprintf(stderr, "Failed to create an archive file!\n");
	}

close_fd:
	close(fd);
ret:
	return err;
}

static void stringify_fw_act_history_timestamp(__u64 timestamp, char *buf, int len)
{
	uint64_t secs, hour;
	uint8_t min, sec;

	memset(buf, 0, sizeof(char) * len);

	secs = le64_to_cpu(timestamp) / 1000;
	hour = secs / 3600;
	min = (secs % 3600) / 60;
	sec = secs % 60;
	sprintf(buf, "%" PRIu64 ":%02" PRIu8 ":%02" PRIu8 "", hour, min, sec);
}

static const char *const fw_act_history_ca_type[] = {
	[0x00] = "000b", [0x01] = "001b", [0x02] = "010b", [0x03] = "011b",
	[0x04] = "100b", [0x05] = "101b", [0x06] = "110b", [0x07] = "111b",
};

static const char *stringify_fw_act_history_ca_type(__u8 ca_type)
{
	return stringify_arg(fw_act_history_ca_type, ARRAY_SIZE(fw_act_history_ca_type), ca_type);
}

static void stringify_fw_act_history_result(__u16 result, char *buf, int len)
{
	memset(buf, 0, sizeof(char) * len);

	if (result == 0)
		sprintf(buf, "pass");
	else
		sprintf(buf, "fail #%" PRIu16 "", le16_to_cpu(result));
}

static void show_fw_act_history_json(struct ocp_fw_act_history *history)
{
	struct json_object *root;
	struct json_object *entry;
	struct json_array *entries;
	__u32 num_entries;
	char buf[32];
	int i;

	root = json_create_object();
	entries = json_create_array();
	num_entries = le32_to_cpu(history->num_entries);

	for (i = 0; i < num_entries; i++) {
		entry = json_create_object();

		json_object_add_value_uint(entry, "firwmare_action_counter", le16_to_cpu(history->entries[i].counter));
		stringify_fw_act_history_timestamp(history->entries[i].timestamp, buf, 32);
		json_object_add_value_string(entry, "power_on_hour", buf);
		json_object_add_value_uint(entry, "power_cycle_count", le64_to_cpu(history->entries[i].power_cycle));
		memset((void *)buf, 0, 32);
		memcpy(buf, (char *)&(history->entries[i].prev_fw), 8);
		json_object_add_value_string(entry, "previous_firmware", buf);
		memset((void *)buf, 0, 32);
		memcpy(buf, (char *)&(history->entries[i].new_fw), 8);
		json_object_add_value_string(entry, "new_firmware_activated", buf);
		json_object_add_value_uint(entry, "slot_number", history->entries[i].slot);
		memset((void *)buf, 0, 32);
		sprintf(buf, "%s", stringify_fw_act_history_ca_type(history->entries[i].ca_type));
		json_object_add_value_string(entry, "commit_action_type", buf);
		stringify_fw_act_history_result(history->entries[i].result, buf, 32);
		json_object_add_value_string(entry, "result", buf);

		json_array_add_value_object(entries, entry);
	}

	json_object_add_value_array(root, "entries", entries);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void show_fw_act_history_normal(struct ocp_fw_act_history *history)
{
	__u32 num_entries;
	char buf[32];
	int i;

	printf("Firmware Activate History Log for NVME device: %s\n", devicename);

	printf("Firmware    Power           Power             Previous  New        Slot    Commit  Result     \n");
	printf("Activation  on Hour         Cycle             Firmware  Firmware   Number  Action             \n");
	printf("Counter                     Count                       Activated          Type               \n");
	printf("----------  --------------  ----------------  --------  ---------  ------  ------  -----------\n");

	num_entries = le32_to_cpu(history->num_entries);

	for (i = 0; i < num_entries; i++) {
		printf("%-10" PRIu16 "  ", le16_to_cpu(history->entries[i].counter));
		stringify_fw_act_history_timestamp(history->entries[i].timestamp, buf, 32);
		printf("%-14s  ", buf);
		printf("%-16" PRIu64 "  ", le64_to_cpu(history->entries[i].power_cycle));
		memset((void *)buf, 0, 32);
		memcpy(buf, (char *)&(history->entries[i].prev_fw), 8);
		printf("%-8s  ", buf);
		memset((void *)buf, 0, 32);
		memcpy(buf, (char *)&(history->entries[i].new_fw), 8);
		printf("%-9s  ", buf);
		printf("%-6" PRIu8 "  ", history->entries[i].slot);
		memset((void *)buf, 0, 32);
		sprintf(buf, "%s", stringify_fw_act_history_ca_type(history->entries[i].ca_type));
		printf("%-6s  ", buf);
		stringify_fw_act_history_result(history->entries[i].result, buf, 32);
		printf("%s\n", buf);
	}
	printf("\n\n");
}

static void show_fw_act_history(struct ocp_fw_act_history *history, enum nvme_print_flags flags)
{
	if (flags & BINARY)
		return d_raw((unsigned char *)history, sizeof(*history));
	else if (flags & JSON)
		return show_fw_act_history_json(history);

	show_fw_act_history_normal(history);
}

static int get_fw_activate_history(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct ocp_fw_act_history history;
	const char *desc = "Retrieve FW activate history table.";
	int flags, err, fd;
	char buf[2 * sizeof(history.log_page_guid) + 3];

	struct config {
		char *output_format;
		int raw_binary;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary", 'b', &cfg.raw_binary, raw),
		OPT_END(),
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0) {
		fprintf(stderr, "Invalid output format: %s\n", cfg.output_format);
		goto close_fd;
	}
	if (cfg.raw_binary)
		flags = BINARY;

	err = nvme_get_log(fd, NVME_NSID_ALL, FADU_LOG_FW_ACTIVATE_HISTORY, false, sizeof(history), &history);
	if (!err) {
		stringify_log_page_guid(history.log_page_guid, buf);
		if (strcmp(buf, "0xd11cf3ac8ab24de2a3f6dab4769a796d"))
			fprintf(stderr, "Invalid GUID: %s\n", buf);
		else
			show_fw_act_history(&history, flags);
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		perror("vs-fw-activate-history");
	}

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static void show_drive_info_json(struct ocp_drive_info *info)
{
	struct json_object *root;
	char buf[20];
	__u16 hw_rev_major, hw_rev_minor;

	root = json_create_object();

	memset((void *)buf, 0, 20);
	hw_rev_major = le32_to_cpu(info->hw_revision) / 10;
	hw_rev_minor = le32_to_cpu(info->hw_revision) % 10;
	sprintf(buf, "%" PRIu32 ".%" PRIu32, hw_rev_major, hw_rev_minor);

	json_object_add_value_string(root, "hw_revision", buf);
	json_object_add_value_uint(root, "ftl_unit_size", le32_to_cpu(info->ftl_unit_size));

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void show_drive_info_normal(struct ocp_drive_info *info)
{
	__u16 hw_rev_major, hw_rev_minor;

	hw_rev_major = le32_to_cpu(info->hw_revision) / 10;
	hw_rev_minor = le32_to_cpu(info->hw_revision) % 10;

	printf("HW Revision   : %" PRIu32 ".%" PRIu32 "\n", hw_rev_major, hw_rev_minor);
	printf("FTL Unit Size : %" PRIu32 "\n", le32_to_cpu(info->ftl_unit_size));
	printf("\n\n");
}

static void show_drive_info(struct ocp_drive_info *info, enum nvme_print_flags flags)
{
	if (flags & BINARY)
		return d_raw((unsigned char *)info, sizeof(*info));
	else if (flags & JSON)
		return show_drive_info_json(info);

	show_drive_info_normal(info);
}

static int get_drive_info(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct ocp_drive_info info;
	const char *desc = "Retrieve drive information.";
	int flags, err, fd;
	__u32 data_len;

	struct config {
		char *output_format;
		int raw_binary;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary", 'b', &cfg.raw_binary, raw),
		OPT_END(),
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0) {
		fprintf(stderr, "Invalid output format: %s\n", cfg.output_format);
		goto close_fd;
	}
	if (cfg.raw_binary)
		flags = BINARY;

	data_len = sizeof(info);
	err = nvme_passthru(fd, NVME_IOCTL_ADMIN_CMD, FADU_NVME_ADMIN_VUC_OPCODE, 0, 0, 0,
			    FADU_VUC_SUBOPCODE_VS_DRIVE_INFO, 0, get_num_dwords(data_len), 0, 0, 0, 0, 0, data_len,
			    &info, 0, NULL, 0, NULL);
	if (!err)
		show_drive_info(&info, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("vs-drive-info");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static const char *log_id_to_description(__u8 log_id)
{
	switch (log_id) {
	case NVME_LOG_ERROR:
		return "Error Information Log ID";
	case NVME_LOG_SMART:
		return "Smart/Health Information Log ID";
	case NVME_LOG_FW_SLOT:
		return "Firmware Slot Information Log ID";
	case NVME_LOG_CHANGED_NS:
		return "Changed Namespace List Log ID";
	case NVME_LOG_CMD_EFFECTS:
		return "Commamds Supported and Effects Log ID";
	case NVME_LOG_DEVICE_SELF_TEST:
		return "Device Self-test Log ID";
	case NVME_LOG_TELEMETRY_HOST:
		return "Telemetry Host-initiated Log ID";
	case NVME_LOG_TELEMETRY_CTRL:
		return "Telemetry Controller-initiated Log ID";
	case NVME_LOG_ENDURANCE_GROUP:
		return "Endurance Group Information Log ID";
	case NVME_LOG_ANA:
		return "Asymmetric Namespace Access Log ID";
	case NVME_LOG_RESERVATION:
		return "Reservation Notification Log ID";
	case NVME_LOG_SANITIZE:
		return "Sanitize Status Log ID";
	case FADU_LOG_CLOUD_SMART:
		return "FADU OCP SMART Cloud Attributes Log ID";
	case FADU_LOG_ERROR_RECOVERY:
		return "FADU OCP Log Error Recovery Log ID";
	case FADU_LOG_FW_ACTIVATE_HISTORY:
		return "FADU OCP FW Activation History Log ID";
	default:
		return "FADU Vendor Unique Log ID";
	}
}

static void show_log_page_directory_json(struct ocp_log_page_directory *directory)
{
	struct json_object *root;
	struct json_object *entry;
	struct json_array *entries;
	__u32 num_log_ids;
	__u8 log_id;
	int i;

	root = json_create_object();
	entries = json_create_array();
	num_log_ids = le32_to_cpu(directory->num_log_ids);

	for (i = 0; i < num_log_ids; i++) {
		entry = json_create_object();
		log_id = directory->log_ids[i];

		json_object_add_value_uint(entry, "log_id", log_id);
		json_object_add_value_string(entry, "description", log_id_to_description(log_id));

		json_array_add_value_object(entries, entry);
	}

	json_object_add_value_array(root, "directory", entries);

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void show_log_page_directory_normal(struct ocp_log_page_directory *directory)
{
	__u32 num_log_ids;
	__u8 log_id;
	int i;

	num_log_ids = le32_to_cpu(directory->num_log_ids);
	for (i = 0; i < num_log_ids; i++) {
		log_id = directory->log_ids[i];
		printf("0x%02X: %s\n", log_id, log_id_to_description(log_id));
	}
}

static void show_log_page_directory(struct ocp_log_page_directory *directory, enum nvme_print_flags flags)
{
	if (flags & BINARY)
		return d_raw((unsigned char *)directory, sizeof(*directory));
	else if (flags & JSON)
		return show_log_page_directory_json(directory);

	show_log_page_directory_normal(directory);
}

static int get_log_page_directory(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct ocp_log_page_directory dir;
	const char *desc = "Retrieve log page directory.";
	int flags, err, fd;
	__u32 data_len;

	struct config {
		char *output_format;
		int raw_binary;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_FLAG("raw-binary", 'b', &cfg.raw_binary, raw),
		OPT_END(),
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0) {
		fprintf(stderr, "Invalid output format: %s\n", cfg.output_format);
		goto close_fd;
	}
	if (cfg.raw_binary)
		flags = BINARY;

	data_len = sizeof(dir);
	err = nvme_passthru(fd, NVME_IOCTL_ADMIN_CMD, FADU_NVME_ADMIN_VUC_OPCODE, 0, 0, 0,
			    FADU_VUC_SUBOPCODE_LOG_PAGE_DIR, 0, get_num_dwords(data_len), 0, 0, 0, 0, 0, data_len, &dir,
			    0, NULL, 0, NULL);
	if (!err)
		show_log_page_directory(&dir, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("log-page-directory");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int clear_pcie_correctable_errors(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Clear PCIe correctable errors.";
	int err, fd;
	__u32 value = 1 << 31; /* Bit 31 - clear PCIe correctable count */

	OPT_ARGS(opts) = {
		OPT_END(),
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = nvme_set_feature(fd, 0, FADU_FEAT_CLEAR_PCIE_CORR_ERRORS, value, 0, 0, 0, NULL, NULL);
	if (err < 0)
		perror("clear-pcie-correctable-errors");
	else
		nvme_show_status(err);

	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int clear_fw_activate_history(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Clear FW activation history.";
	int err, fd;
	__u32 value = 1 << 31; /* Bit 31 - Clear Firmware Update History Log */

	OPT_ARGS(opts) = {
		OPT_END(),
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = nvme_set_feature(fd, 0, FADU_FEAT_CLEAR_FW_UPDATE_HISTORY, value, 0, 0, 0, NULL, NULL);
	if (err < 0)
		perror("clear-fw-activate-history");
	else
		nvme_show_status(err);

	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int set_telemetry_ctrl_option(int fd, __u32 mode)
{
	int err;

	err = nvme_passthru(fd, NVME_IOCTL_ADMIN_CMD, FADU_NVME_ADMIN_VUC_OPCODE, 0, 0, 0,
			    FADU_VUC_SUBOPCODE_SET_TELEMETRY_MODE, 0, 0, 0, mode, 0, 0, 0, 0, NULL, 0, NULL, 0, NULL);

	if (!err)
		printf("%s successfully\n", mode ? "enabled" : "disabled");

	return err;
}

static int get_telemetry_ctrl_option(int fd)
{
	__u32 data_len, data;
	int err;

	data_len = sizeof(data);
	err = nvme_passthru(fd, NVME_IOCTL_ADMIN_CMD, FADU_NVME_ADMIN_VUC_OPCODE, 0, 0, 0,
			    FADU_VUC_SUBOPCODE_GET_TELEMETRY_MODE, 0, get_num_dwords(data_len), 0, 0, 0, 0, 0, data_len,
			    &data, 0, NULL, 1, NULL);
	if (!err)
		printf("%s\n", data ? "enabled" : "disabled");

	return err;
}

static int control_telemetry_ctrl_option(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Control controller-initiated telemetry log page.";
	char *enable = "Enable controller-initiated telemetry";
	char *disable = "Disable controller-initiated telemetry";
	char *status = "Displays controller-initiated telemetry status";
	int err, fd;

	struct config {
		int enable;
		int disable;
		int status;
	};

	struct config cfg = {
		.enable = 0,
		.disable = 0,
		.status = 0,
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("enable", 'e', &cfg.enable, enable),
		OPT_FLAG("disable", 'd', &cfg.disable, disable),
		OPT_FLAG("status", 's', &cfg.status, status),
		OPT_END(),
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	if ((cfg.enable + cfg.disable + cfg.status) != 1) {
		fprintf(stderr, "Only one option allowed at a time!\n");
		goto close_fd;
	}

	if (cfg.enable)
		err = set_telemetry_ctrl_option(fd, 1);
	else if (cfg.disable)
		err = set_telemetry_ctrl_option(fd, 0);
	else if (cfg.status)
		err = get_telemetry_ctrl_option(fd);

	if (err > 0) {
		nvme_show_status(err);
	} else if (err > 0) {
		perror("vs-telemetry-controller-option");
	}

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int cloud_ssd_plugin_version(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	printf("cloud ssd plugin version: %d.%d\n", plugin_version_major, plugin_version_minor);
	return 0;
}