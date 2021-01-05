#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <unistd.h>

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
    FADU_LOG_SMART_CLOUD_ATTRIBUTES = 0xC0,
    FADU_LOG_FW_ACTIVATE_HISTORY    = 0xC2,
};

enum {
    FADU_FEAT_CLEAR_FW_UPDATE_HISTORY = 0xC1,
    FADU_FEAT_CLEAR_PCIE_CORR_ERRORS  = 0xC3,
};

enum {
    FADU_VUC_SUBOPCODE_VS_DRIVE_INFO      = 0x00080101,
};

struct fadu_bad_nand_block_count {
    __u64 raw_count     : 48;
    __u16 normalized    : 16;
};

struct fadu_e2e_correction_count {
    __u32 corrected;
    __u32 detected;
};

struct fadu_user_data_erase_count {
    __u32 maximum;
    __u32 minimum;
};

struct fadu_thermal_status {
    __u8 status;
    __u8 count;
};

struct fadu_cloud_attrs_log {
    __u8  physical_media_units_written[16];
    __u8  physical_media_units_read[16];
    struct fadu_bad_nand_block_count    bad_user_nand_blocks;
    struct fadu_bad_nand_block_count    bad_system_nand_blocks;
    __u64 xor_recovery_count;
    __u64 uncorrectable_read_error_count;
    __u64 soft_ecc_error_count;
    struct fadu_e2e_correction_count    e2e_correction_counts;
    __u8  system_data_percent_used;
    __u64 refresh_counts    : 56;
    struct fadu_user_data_erase_count   user_data_erase_counts;
    struct fadu_thermal_status          thermal_status;
    __u8  rsvd98[6];
    __u64 pcie_correctable_error_count;
    __u32 incomplete_shutdowns;
    __u8  rsvd116[4];
    __u8  percent_free_blocks;
    __u8  rsvd121[7];
    __u16 capacitor_health;
    __u8  rsvd130[6];
    __u64 unaligned_io;
    __u64 security_version_number;
    __u64 nuse;
    __u8  plp_start_count[16];
    __u8  endurance_estimate[16];
    __u8  rsvd192[302];
    __u16 log_page_version;
    __u8  log_page_guid[16];
};

struct __attribute__((packed)) fadu_fw_act_history_entry {
    __u8  version;
    __u8  length;
    __u8  rsvd2[2];
    __u16 counter;
    __u64 timestamp;
    __u8  rsvd14[8];
    __u64 power_cycle;
    __u8  prev_fw[8];
    __u8  new_fw[8];
    __u8  slot;
    __u8  ca_type;
    __u16 result;
    __u8  rsvd50[14];
};

struct __attribute__((packed)) fadu_fw_act_history {
    __u8 log_id;
    __u8 rsvd1[3];
    __u32 num_entries;
    struct fadu_fw_act_history_entry entries[20];
    __u8 rsvd1288[2790];
    __u16 log_page_version;
    __u8  log_page_guid[16];
};

struct fadu_drive_info {
    __u32 drive_hw_revision;
    __u32 ftl_unit_size;
};

static const int plugin_version_major = 1;
static const int plugin_version_minor = 0;

static const char *output_format_no_binary = "Output format: normal|json";

static long double int128_to_double(__u8 *data)
{
    long double result = 0;
    int i;

    for (i = 0; i < 16; i++) {
        result *= 256;
        result += data[15 - i];
    }

    return result;
}

static unsigned int get_num_dwords(unsigned int byte_len) {
    unsigned int num_dwords;

    num_dwords = byte_len / 4;
    if (byte_len % 4 != 0)
        num_dwords += 1;
    
    return num_dwords;
}

static char *current_thermal_status_to_string(__u8 status) {
    switch (status) {
    case 0x00:
        return "Unthrottled";
    case 0x01:
        return "First Level Throttle";
    case 0x02:
        return "Second Level Throttle";
    case 0x03:
        return "Third Level Throttle";
    default:
        return "Invalid Status";
    }
}

void fadu_print_cloud_attrs_log_json(struct fadu_cloud_attrs_log *cloud_attrs_log)
{
	struct json_object *root;
    struct json_object *bad_user_nand_blocks;
    struct json_object *bad_system_nand_blocks;
    struct json_object *e2e_correction_counts;
    struct json_object *user_data_erase_counts;
    struct json_object *thermal_status;
    char log_page_guid_buf[2 * sizeof(cloud_attrs_log->log_page_guid) + 3];
    char *log_page_guid = log_page_guid_buf;
    int i;

    root = json_create_object();

    json_object_add_value_float(root, "physical_media_units_written",
        int128_to_double(cloud_attrs_log->physical_media_units_written));
    json_object_add_value_float(root, "physical_media_units_read",
        int128_to_double(cloud_attrs_log->physical_media_units_read));
    
    bad_user_nand_blocks = json_create_object();

    json_object_add_value_uint(bad_user_nand_blocks, "normalized_value", 
        le16_to_cpu(cloud_attrs_log->bad_user_nand_blocks.normalized));
    json_object_add_value_uint(bad_user_nand_blocks, "raw_count", 
        le64_to_cpu(cloud_attrs_log->bad_user_nand_blocks.raw_count));
    json_object_add_value_object(root, "bad_user_nand_blocks", bad_user_nand_blocks);

    bad_system_nand_blocks = json_create_object();

    json_object_add_value_uint(bad_system_nand_blocks, "normalized_value", 
        le16_to_cpu(cloud_attrs_log->bad_system_nand_blocks.normalized));
    json_object_add_value_uint(bad_system_nand_blocks, "raw_count", 
        le64_to_cpu(cloud_attrs_log->bad_system_nand_blocks.raw_count));
    json_object_add_value_object(root, "bad_system_nand_blocks", bad_system_nand_blocks);

    json_object_add_value_uint(root, "xor_recovery_count",
        le64_to_cpu(cloud_attrs_log->xor_recovery_count));
    json_object_add_value_uint(root, "uncorrectable_read_error_count",
        le64_to_cpu(cloud_attrs_log->uncorrectable_read_error_count));
    json_object_add_value_uint(root, "soft_ecc_error_count",
        le64_to_cpu(cloud_attrs_log->soft_ecc_error_count));

    e2e_correction_counts = json_create_object();

    json_object_add_value_uint(e2e_correction_counts, "corrected_errors", 
        le32_to_cpu(cloud_attrs_log->e2e_correction_counts.corrected));
    json_object_add_value_uint(e2e_correction_counts, "detected_errors", 
        le32_to_cpu(cloud_attrs_log->e2e_correction_counts.detected));
    json_object_add_value_object(root, "e2e_correction_counts", e2e_correction_counts);

    json_object_add_value_uint(root, "system_data_percent_used",
       cloud_attrs_log->system_data_percent_used);
    json_object_add_value_uint(root, "refresh_counts",
        le64_to_cpu(cloud_attrs_log->refresh_counts));

    user_data_erase_counts = json_create_object();

    json_object_add_value_uint(user_data_erase_counts, "minimum_user_data_erase_count", 
        le32_to_cpu(cloud_attrs_log->user_data_erase_counts.minimum));
    json_object_add_value_uint(user_data_erase_counts, "maximum_user_data_erase_count", 
        le32_to_cpu(cloud_attrs_log->user_data_erase_counts.maximum));
    json_object_add_value_object(root, "user_data_erase_counts", user_data_erase_counts);

    thermal_status = json_create_object();

    json_object_add_value_string(thermal_status, "current_throttling_status", 
        current_thermal_status_to_string(cloud_attrs_log->thermal_status.status));
    json_object_add_value_uint(thermal_status, "number_of_thermal_throttling_events", 
        cloud_attrs_log->thermal_status.count);
    json_object_add_value_object(root, "thermal_throttling_status_and_count", thermal_status);

    json_object_add_value_uint(root, "pcie_correctable_error_count", 
        le64_to_cpu(cloud_attrs_log->pcie_correctable_error_count));
    json_object_add_value_uint(root, "incomplete_shutdowns", 
        le32_to_cpu(cloud_attrs_log->incomplete_shutdowns));
    json_object_add_value_uint(root, "percent_free_blocks", 
        cloud_attrs_log->percent_free_blocks);
    json_object_add_value_uint(root, "capacitor_health", 
        le16_to_cpu(cloud_attrs_log->capacitor_health));
    json_object_add_value_uint(root, "unaligned_io", 
        le64_to_cpu(cloud_attrs_log->unaligned_io));
    json_object_add_value_uint(root, "security_version_number", 
        le64_to_cpu(cloud_attrs_log->security_version_number));
    json_object_add_value_uint(root, "nuse", 
        le64_to_cpu(cloud_attrs_log->nuse));
    json_object_add_value_float(root, "plp_start_count",
        int128_to_double(cloud_attrs_log->plp_start_count));
    json_object_add_value_float(root, "endurance_estimate",
        int128_to_double(cloud_attrs_log->endurance_estimate));
    json_object_add_value_uint(root, "log_page_version", 
        le16_to_cpu(cloud_attrs_log->log_page_version));

    memset(log_page_guid, 0, sizeof(log_page_guid_buf));
    log_page_guid += sprintf(log_page_guid, "0x");
    for (i = 0; i < sizeof(cloud_attrs_log->log_page_guid); i++)
        log_page_guid += sprintf(log_page_guid, "%x", cloud_attrs_log->log_page_guid[15 - i]);

	json_object_add_value_string(root, "log_page_guid", log_page_guid_buf);

    json_print_object(root, NULL);
    printf("\n");
    json_free_object(root);
}

void fadu_print_cloud_attrs_log_normal(struct fadu_cloud_attrs_log *cloud_attrs_log)
{
    char log_page_guid_buf[2 * sizeof(cloud_attrs_log->log_page_guid) + 3];
    char *log_page_guid = log_page_guid_buf;
    int i;

    printf("Smart Extended Log for NVME device:%s\n", devicename);

    printf("Physical Media Units Written                           : %'.0Lf\n",
        int128_to_double(cloud_attrs_log->physical_media_units_written));
    printf("Physical Media Units Read                              : %'.0Lf\n",
        int128_to_double(cloud_attrs_log->physical_media_units_read));
    printf("Bad User NAND Blocks (Normalized)                      : %"PRIu16"%%\n",
        le16_to_cpu(cloud_attrs_log->bad_user_nand_blocks.normalized));
    printf("Bad User NAND Blocks (Raw)                             : %"PRIu64"\n",
        le64_to_cpu(cloud_attrs_log->bad_user_nand_blocks.raw_count));
    printf("Bad System NAND Blocks (Normalized)                    : %"PRIu16"%%\n",
        le16_to_cpu(cloud_attrs_log->bad_system_nand_blocks.normalized));
    printf("Bad System NAND Blocks (Raw)                           : %"PRIu64"\n",
        le64_to_cpu(cloud_attrs_log->bad_system_nand_blocks.raw_count));
    printf("XOR Recovery Count                                     : %"PRIu64"\n",
        le64_to_cpu(cloud_attrs_log->xor_recovery_count));
    printf("Uncorrectable Read Error Count                         : %"PRIu64"\n",
        le64_to_cpu(cloud_attrs_log->uncorrectable_read_error_count));
    printf("Soft ECC Error Count                                   : %"PRIu64"\n",
        le64_to_cpu(cloud_attrs_log->soft_ecc_error_count));
    printf("End to End Correction Counts (Corrected)               : %"PRIu32"\n",
        le32_to_cpu(cloud_attrs_log->e2e_correction_counts.corrected));
    printf("End to End Correction Counts (Detected)                : %"PRIu32"\n",
        le32_to_cpu(cloud_attrs_log->e2e_correction_counts.detected));
    printf("System Data %% Used                                     : %"PRIu8"%%\n",
        cloud_attrs_log->system_data_percent_used);
    printf("Refresh Counts                                         : %"PRIu64"\n",
        le64_to_cpu(cloud_attrs_log->refresh_counts));
    printf("User Data Erase Counts (Minimum)                       : %"PRIu32"\n",
        le32_to_cpu(cloud_attrs_log->user_data_erase_counts.minimum));
    printf("User Data Erase Counts (Maximum)                       : %"PRIu32"\n",
        le32_to_cpu(cloud_attrs_log->user_data_erase_counts.maximum));
    printf("Thermal Throttling Status and Count (Current Status)   : %s\n",
        current_thermal_status_to_string(cloud_attrs_log->thermal_status.status));
    printf("Thermal Throttling Status and Count (Number of Events) : %"PRIu8"\n",
        cloud_attrs_log->thermal_status.count);
    printf("PCIe Correctable Error Count                           : %"PRIu64"\n",
        le64_to_cpu(cloud_attrs_log->pcie_correctable_error_count));
    printf("Incomplete Shutdowns                                   : %"PRIu32"\n",
        le32_to_cpu(cloud_attrs_log->incomplete_shutdowns));
    printf("%% Free Blocks                                          : %"PRIu8"%%\n",
        cloud_attrs_log->percent_free_blocks);
    printf("Capacitor Health                                       : %"PRIu16"%%\n",
        le16_to_cpu(cloud_attrs_log->capacitor_health));
    printf("Unaligned IO                                           : %"PRIu64"\n",
        le64_to_cpu(cloud_attrs_log->unaligned_io));
    printf("Security Version Number                                : %"PRIu64"\n",
        le64_to_cpu(cloud_attrs_log->security_version_number));
    printf("NUSE                                                   : %"PRIu64"\n",
        le64_to_cpu(cloud_attrs_log->nuse));
    printf("PLP Start Count                                        : %'.0Lf\n",
        int128_to_double(cloud_attrs_log->plp_start_count));
    printf("Endurance Estimate                                     : %'.0Lf\n",
        int128_to_double(cloud_attrs_log->endurance_estimate));
    printf("Log Page Version                                       : %"PRIu16"\n",
        le16_to_cpu(cloud_attrs_log->log_page_version));
    
    memset(log_page_guid, 0, sizeof(log_page_guid_buf));
    log_page_guid += sprintf(log_page_guid, "0x");
    for (i = 0; i < sizeof(cloud_attrs_log->log_page_guid); i++)
        log_page_guid += sprintf(log_page_guid, "%x", cloud_attrs_log->log_page_guid[15 - i]);

    printf("Log Page GUID                                          : %s\n", log_page_guid_buf);
    printf("\n\n");
}

void fadu_print_cloud_attrs_log(struct fadu_cloud_attrs_log *cloud_attrs_log, enum nvme_print_flags flags)
{
    if (flags & JSON) {
        fadu_print_cloud_attrs_log_json(cloud_attrs_log);
        return;
    }

    fadu_print_cloud_attrs_log_normal(cloud_attrs_log);
}

static const char *commit_action_type_to_string(__u8 ca_type) {
    const char *ca_values[8] = { "000b", "001b", "010b", "011b", "100b", "101b", "110b", "111b" };

    return ca_values[ca_type & 7];
}

void fadu_print_fw_act_history_json(struct fadu_fw_act_history *fw_act_history) {
	struct json_object *root;
    struct json_object *entry;
    struct json_array *entries;
    __u32 num_entries = le32_to_cpu(fw_act_history->num_entries);
    struct fadu_fw_act_history_entry *fw_act_history_entry;
    char timestamp_buf[20];
	char prev_fw_buf[9];
	char new_fw_buf[9];
	char ca_type_buf[8];
    char result_buf[12];    
    uint64_t timestamp, hour;
    uint8_t  min, sec;
    int i;

    root = json_create_object();
    entries = json_create_array();

    for (i = 0; i < num_entries; i++) {
        fw_act_history_entry = &fw_act_history->entries[i];

        memset((void *) timestamp_buf, 0, 20);
        memset((void *) prev_fw_buf, 0, 9);
        memset((void *) new_fw_buf, 0, 9);
        memset((void *) ca_type_buf, 0, 8);
        memset((void *) result_buf, 0, 12);

        timestamp = le64_to_cpu(fw_act_history_entry->timestamp) / 1000;
        hour = timestamp / 3600;
        min = (timestamp % 3600) / 60;
        sec = timestamp % 60;
        sprintf(timestamp_buf, "%"PRIu64":%02"PRIu8":%02"PRIu8"", hour, min, sec);

        memcpy(prev_fw_buf, (char *) &(fw_act_history_entry->prev_fw), 8);
        memcpy(new_fw_buf, (char *) &(fw_act_history_entry->new_fw), 8);

        if (fw_act_history_entry->result == 0)
            sprintf(result_buf, "pass");
        else
            sprintf(result_buf, "fail #%"PRIu16"", le16_to_cpu(fw_act_history_entry->result));

        entry = json_create_object();

        json_object_add_value_uint(entry, "firwmare_action_counter", 
            le16_to_cpu(fw_act_history_entry->counter));
        json_object_add_value_string(entry, "power_on_hour", timestamp_buf);
        json_object_add_value_uint(entry, "power_cycle_count", 
            le64_to_cpu(fw_act_history_entry->power_cycle));
        json_object_add_value_string(entry, "previous_firmware", prev_fw_buf);
        json_object_add_value_string(entry, "new_firmware_activated", new_fw_buf);
        json_object_add_value_uint(entry, "slot_number", fw_act_history_entry->power_cycle);
        json_object_add_value_string(entry, "commit_action_type", ca_type_buf);
        json_object_add_value_string(entry, "result", result_buf);

        json_array_add_value_object(entries, entry);
    }

	json_object_add_value_array(root, "entries", entries);

    json_print_object(root, NULL);
    printf("\n");
    json_free_object(root);
}

void fadu_print_fw_act_history_normal(struct fadu_fw_act_history *fw_act_history) {
    __u32 num_entries = le32_to_cpu(fw_act_history->num_entries);
    struct fadu_fw_act_history_entry *fw_act_history_entry;
    char timestamp_buf[20];
	char prev_fw_buf[9];
	char new_fw_buf[9];
	char ca_type_buf[8];    
    uint64_t timestamp, hour;
    uint8_t  min, sec;
    int i;

    printf("Firmware Activate History Log for NVME device:%s\n", devicename);

    printf("Firmware    Power           Power             Previous  New        Slot    Commit  Result     \n");
    printf("Activation  on Hour         Cycle             Firmware  Firmware   Number  Action             \n");
    printf("Counter                     Count                       Activated          Type               \n");
    printf("----------  --------------  ----------------  --------  ---------  ------  ------  -----------\n");

    for (i = 0; i < num_entries; i++) {
        fw_act_history_entry = &fw_act_history->entries[i];

        memset((void *)timestamp_buf, 0, 20);
        memset((void *)prev_fw_buf, 0, 9);
        memset((void *)new_fw_buf, 0, 9);
        memset((void *)ca_type_buf, 0, 8);

        timestamp = le64_to_cpu(fw_act_history_entry->timestamp) / 1000;
        hour = timestamp / 3600;
        min = (timestamp % 3600) / 60;
        sec = timestamp % 60;
        sprintf(timestamp_buf, "%"PRIu64":%02"PRIu8":%02"PRIu8"", hour, min, sec);

        memcpy(prev_fw_buf, (char *) &(fw_act_history_entry->prev_fw), 8);
        memcpy(new_fw_buf, (char *) &(fw_act_history_entry->new_fw), 8);

        printf("%-10"PRIu16"  ", le16_to_cpu(fw_act_history_entry->counter));
        printf("%-14s  ", timestamp_buf);
        printf("%-16"PRIu64"  ", le64_to_cpu(fw_act_history_entry->power_cycle));
        printf("%-8s  ", prev_fw_buf);
        printf("%-9s  ", new_fw_buf);
        printf("%-6"PRIu8"  ", fw_act_history_entry->slot);
        printf("%-6s  ", commit_action_type_to_string(fw_act_history_entry->ca_type));

        if (fw_act_history_entry->result == 0)
            printf("pass\n");
        else
            printf("fail #%"PRIu16"\n", le16_to_cpu(fw_act_history_entry->result));
    }
    printf("\n\n");
}

void fadu_print_fw_act_history(struct fadu_fw_act_history *fw_act_history, enum nvme_print_flags flags)
{
    if (flags & JSON) {
        fadu_print_fw_act_history_json(fw_act_history);
        return;
    }

    fadu_print_fw_act_history_normal(fw_act_history);
}

void fadu_print_drive_info_json(struct fadu_drive_info *drive_info) {
    struct json_object *root;
    char hw_rev_buf[20];
    __u16 hw_rev_major, hw_rev_minor;

    root = json_create_object();

    memset((void *) hw_rev_buf, 0, 20);

    hw_rev_major = le32_to_cpu(drive_info->drive_hw_revision) / 10;
    hw_rev_minor = le32_to_cpu(drive_info->drive_hw_revision) % 10;

    sprintf(hw_rev_buf, "%"PRIu32".%"PRIu32, hw_rev_major, hw_rev_minor);

    json_object_add_value_string(root, "drive_hw_revision", hw_rev_buf);
    json_object_add_value_uint(root, "ftl_unit_size", le32_to_cpu(drive_info->ftl_unit_size));
    
    json_print_object(root, NULL);
    printf("\n");
    json_free_object(root);
}

void fadu_print_drive_info_normal(struct fadu_drive_info *drive_info) {
    __u16 hw_rev_major, hw_rev_minor;

    hw_rev_major = le32_to_cpu(drive_info->drive_hw_revision) / 10;
    hw_rev_minor = le32_to_cpu(drive_info->drive_hw_revision) % 10;

    printf("Drive HW Revision : %"PRIu32".%"PRIu32"\n", hw_rev_major, hw_rev_minor);
    printf("FTL Unit Size     : %"PRIu32"\n", le32_to_cpu(drive_info->ftl_unit_size));
    printf("\n\n");
}

void fadu_print_drive_info(struct fadu_drive_info *drive_info, enum nvme_print_flags flags)
{
    if (flags & JSON) {
        fadu_print_drive_info_json(drive_info);
        return;
    }

    fadu_print_drive_info_normal(drive_info);
}

static int fadu_vs_smart_add_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
    struct fadu_cloud_attrs_log cloud_attrs_log;
	const char *desc ="Retrieve SMART Cloud Attributes log for the given device.";
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format_no_binary),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	err = nvme_get_log(fd, NVME_NSID_ALL, FADU_LOG_SMART_CLOUD_ATTRIBUTES,
        false, sizeof(cloud_attrs_log), &cloud_attrs_log);
	if (!err)
		fadu_print_cloud_attrs_log(&cloud_attrs_log, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("vs-smart-add-log");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int fadu_vs_internal_log(int argc, char **argv, struct command *cmd, struct plugin *plugin) { return 0; }

static int fadu_vs_fw_activate_history(int argc, char **argv, struct command *cmd, struct plugin *plugin) { 
    struct fadu_fw_act_history fw_act_history;
	const char *desc ="Retrieve FW activate history table for the given device.";
	enum nvme_print_flags flags;
	int err, fd;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format_no_binary),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

	err = nvme_get_log(fd, NVME_NSID_ALL, FADU_LOG_FW_ACTIVATE_HISTORY,
        false, sizeof(fw_act_history), &fw_act_history);
	if (!err)
		fadu_print_fw_act_history(&fw_act_history, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("vs-fw-activate-history");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int fadu_vs_drive_info(int argc, char **argv, struct command *cmd, struct plugin *plugin) {
    struct fadu_drive_info drive_info;
	const char *desc ="Retrieve Drive Info for the given device.";
	enum nvme_print_flags flags;
	int err, fd;
    __u32 data_len;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format_no_binary),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0)
		goto close_fd;

    data_len = sizeof(drive_info);

    err = nvme_passthru(fd, NVME_IOCTL_ADMIN_CMD, FADU_NVME_ADMIN_VUC_OPCODE, 0, 0,
        0, FADU_VUC_SUBOPCODE_VS_DRIVE_INFO, 0, get_num_dwords(data_len), 0, 0, 0, 0, 0,
        data_len, &drive_info, 0, NULL, 0, NULL);
	if (!err)
		fadu_print_drive_info(&drive_info, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("vs-drive-info");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int fadu_clear_pcie_correctable_errors(int argc, char **argv, struct command *cmd, struct plugin *plugin) {
	const char *desc ="Clear PCIe correctable errors for the given device.";
	int err, fd;
	__u32 value = 1 << 31; /* Bit 31 - clear PCIe correctable count */

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

    err = nvme_set_feature(fd, 0, FADU_FEAT_CLEAR_PCIE_CORR_ERRORS, value,
	    0, 0, 0, NULL, NULL);
	if (err < 0)
		perror("clear-pcie-correctable-errors");
	else
		nvme_show_status(err);

	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int fadu_clear_fw_activate_history(int argc, char **argv, struct command *cmd, struct plugin *plugin) {
	const char *desc ="Clear FW activation history for the given device.";
	int err, fd;
	__u32 value = 1 << 31; /* Bit 31 - Clear Firmware Update History Log */

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

    err = nvme_set_feature(fd, 0, FADU_FEAT_CLEAR_FW_UPDATE_HISTORY, value,
	    0, 0, 0, NULL, NULL);
	if (err < 0)
		perror("clear-fw-activate-history");
	else
		nvme_show_status(err);

	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int fadu_log_page_directory(int argc, char **argv, struct command *cmd, struct plugin *plugin) { return 0; }

static int fadu_cloud_ssd_plugin_version(int argc, char **argv, struct command *cmd, struct plugin *plugin) {
    printf("cloud ssd plugin version: %d.%d\n", plugin_version_major, plugin_version_minor);
    return 0;
}

static int fadu_telemetry_controller_option(int argc, char **argv, struct command *cmd, struct plugin *plugin) { return 0; }
