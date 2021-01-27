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
    FADU_LOG_ERROR_RECOVERY         = 0xC1,
    FADU_LOG_FW_ACTIVATE_HISTORY    = 0xC2,
};

enum {
    FADU_FEAT_CLEAR_FW_UPDATE_HISTORY = 0xC1,
    FADU_FEAT_CLEAR_PCIE_CORR_ERRORS  = 0xC3,
};

enum {
    FADU_VUC_SUBOPCODE_VS_DRIVE_INFO      = 0x00080101,
    FADU_VUC_SUBOPCODE_LOG_PAGE_DIR       = 0x00080901,
    FADU_VUC_SUBOPCODE_GET_TELEMETRY_MODE = 0x000C0101,
    FADU_VUC_SUBOPCODE_SET_TELEMETRY_MODE = 0x000C0000,
};

enum fadu_ctrl_option_flags {
    FADU_CTRL_OPTION_ENABLE = 0,
    FADU_CTRL_OPTION_DISABLE = 1,
    FADU_CTRL_OPTION_STATUS = 2,
};

struct fadu_bad_nand_block_count {
    __u64 raw           : 48;
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
    __u8 num_events;
    __u8 current_status;
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
    __u32 hw_revision;
    __u32 ftl_unit_size;
};

struct fadu_log_page_directory {
    __u32 num_log_ids;
    __u8  rsvd4[12];
    __u8  log_ids[256];
    __u8  rsvd272[240];
};

static const int plugin_version_major = 1;
static const int plugin_version_minor = 0;

enum fadu_ctrl_option_flags validate_fadu_ctrl_option(char *format)
{
	if (!format)
		return -EINVAL;
	if (!strcmp(format, "enable"))
		return FADU_CTRL_OPTION_ENABLE;
	if (!strcmp(format, "disable"))
		return FADU_CTRL_OPTION_DISABLE;
	if (!strcmp(format, "status"))
		return FADU_CTRL_OPTION_STATUS;
	return -EINVAL;
}

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

static bool invalid_log_page_guid(__u8 *expected_guid, __u8 *actual_guid) {
    int i;

    for (i = 0; i < 16; i++) {
        if (expected_guid[i] != actual_guid[i])	{
            return true;
        }
    }

    return false;
}

static char *current_thermal_status_to_string(__u8 status) {
    switch (status) {
    case 0x00:
        return "unthrottled";
    case 0x01:
        return "first_level";
    case 0x02:
        return "second_level";
    case 0x03:
        return "third_level";
    default:
        return "invalid";
    }
}

void print_fadu_cloud_attrs_log_json(struct fadu_cloud_attrs_log *log)
{
	struct json_object *root;
    struct json_object *bad_user_nand_blocks;
    struct json_object *bad_system_nand_blocks;
    struct json_object *e2e_correction_counts;
    struct json_object *user_data_erase_counts;
    struct json_object *thermal_status;
    char log_page_guid_buf[2 * sizeof(log->log_page_guid) + 3];
    char *log_page_guid = log_page_guid_buf;
    int i;

    root = json_create_object();

    json_object_add_value_float(root, "physical_media_units_written",
        int128_to_double(log->physical_media_units_written));
    json_object_add_value_float(root, "physical_media_units_read",
        int128_to_double(log->physical_media_units_read));
    
    bad_user_nand_blocks = json_create_object();

    json_object_add_value_uint(bad_user_nand_blocks, "normalized", 
        le16_to_cpu(log->bad_user_nand_blocks.normalized));
    json_object_add_value_uint(bad_user_nand_blocks, "raw", 
        le64_to_cpu(log->bad_user_nand_blocks.raw));
    json_object_add_value_object(root, "bad_user_nand_blocks", bad_user_nand_blocks);

    bad_system_nand_blocks = json_create_object();

    json_object_add_value_uint(bad_system_nand_blocks, "normalized", 
        le16_to_cpu(log->bad_system_nand_blocks.normalized));
    json_object_add_value_uint(bad_system_nand_blocks, "raw", 
        le64_to_cpu(log->bad_system_nand_blocks.raw));
    json_object_add_value_object(root, "bad_system_nand_blocks", bad_system_nand_blocks);

    json_object_add_value_uint(root, "xor_recovery_count", le64_to_cpu(log->xor_recovery_count));
    json_object_add_value_uint(root, "uncorrectable_read_error_count",
        le64_to_cpu(log->uncorrectable_read_error_count));
    json_object_add_value_uint(root, "soft_ecc_error_count",
        le64_to_cpu(log->soft_ecc_error_count));

    e2e_correction_counts = json_create_object();

    json_object_add_value_uint(e2e_correction_counts, "corrected", 
        le32_to_cpu(log->e2e_correction_counts.corrected));
    json_object_add_value_uint(e2e_correction_counts, "detected", 
        le32_to_cpu(log->e2e_correction_counts.detected));
    json_object_add_value_object(root, "e2e_correction_counts", e2e_correction_counts);

    json_object_add_value_uint(root, "system_data_percent_used", log->system_data_percent_used);
    json_object_add_value_uint(root, "refresh_counts", le64_to_cpu(log->refresh_counts));

    user_data_erase_counts = json_create_object();

    json_object_add_value_uint(user_data_erase_counts, "minimum",
        le32_to_cpu(log->user_data_erase_counts.minimum));
    json_object_add_value_uint(user_data_erase_counts, "maximum", 
        le32_to_cpu(log->user_data_erase_counts.maximum));
    json_object_add_value_object(root, "user_data_erase_counts", user_data_erase_counts);

    thermal_status = json_create_object();

    json_object_add_value_string(thermal_status, "current_status", 
        current_thermal_status_to_string(log->thermal_status.current_status));
    json_object_add_value_uint(thermal_status, "num_events", log->thermal_status.num_events);
    json_object_add_value_object(root, "thermal_status", thermal_status);

    json_object_add_value_uint(root, "pcie_correctable_error_count",
        le64_to_cpu(log->pcie_correctable_error_count));
    json_object_add_value_uint(root, "incomplete_shutdowns", 
        le32_to_cpu(log->incomplete_shutdowns));
    json_object_add_value_uint(root, "percent_free_blocks", log->percent_free_blocks);
    json_object_add_value_uint(root, "capacitor_health", le16_to_cpu(log->capacitor_health));
    json_object_add_value_uint(root, "unaligned_io", le64_to_cpu(log->unaligned_io));
    json_object_add_value_uint(root, "security_version_number",
        le64_to_cpu(log->security_version_number));
    json_object_add_value_uint(root, "nuse", le64_to_cpu(log->nuse));
    json_object_add_value_float(root, "plp_start_count", int128_to_double(log->plp_start_count));
    json_object_add_value_float(root, "endurance_estimate",
        int128_to_double(log->endurance_estimate));
    json_object_add_value_uint(root, "log_page_version", le16_to_cpu(log->log_page_version));

    memset(log_page_guid, 0, sizeof(log_page_guid_buf));
    log_page_guid += sprintf(log_page_guid, "0x");
    for (i = 0; i < sizeof(log->log_page_guid); i++)
        log_page_guid += sprintf(log_page_guid, "%x", log->log_page_guid[15 - i]);

	json_object_add_value_string(root, "log_page_guid", log_page_guid_buf);

    json_print_object(root, NULL);
    printf("\n");
    json_free_object(root);
}

void print_fadu_cloud_attrs_log_normal(struct fadu_cloud_attrs_log *log)
{
    char log_page_guid_buf[2 * sizeof(log->log_page_guid) + 3];
    char *log_page_guid = log_page_guid_buf;
    int i;

    printf("Smart Extended Log for NVME device:%s\n", devicename);

    printf("Physical Media Units Written                 : %'.0Lf\n",
        int128_to_double(log->physical_media_units_written));
    printf("Physical Media Units Read                    : %'.0Lf\n",
        int128_to_double(log->physical_media_units_read));
    printf("Bad User NAND Blocks (Normalized)            : %"PRIu16"%%\n",
        le16_to_cpu(log->bad_user_nand_blocks.normalized));
    printf("Bad User NAND Blocks (Raw)                   : %"PRIu64"\n",
        le64_to_cpu(log->bad_user_nand_blocks.raw));
    printf("Bad System NAND Blocks (Normalized)          : %"PRIu16"%%\n",
        le16_to_cpu(log->bad_system_nand_blocks.normalized));
    printf("Bad System NAND Blocks (Raw)                 : %"PRIu64"\n",
        le64_to_cpu(log->bad_system_nand_blocks.raw));
    printf("XOR Recovery Count                           : %"PRIu64"\n",
        le64_to_cpu(log->xor_recovery_count));
    printf("Uncorrectable Read Error Count               : %"PRIu64"\n",
        le64_to_cpu(log->uncorrectable_read_error_count));
    printf("Soft ECC Error Count                         : %"PRIu64"\n",
        le64_to_cpu(log->soft_ecc_error_count));
    printf("End to End Correction Counts (Corrected)     : %"PRIu32"\n",
        le32_to_cpu(log->e2e_correction_counts.corrected));
    printf("End to End Correction Counts (Detected)      : %"PRIu32"\n",
        le32_to_cpu(log->e2e_correction_counts.detected));
    printf("System Data %% Used                           : %"PRIu8"%%\n",
        log->system_data_percent_used);
    printf("Refresh Counts                               : %"PRIu64"\n",
        le64_to_cpu(log->refresh_counts));
    printf("User Data Erase Counts (Minimum)             : %"PRIu32"\n",
        le32_to_cpu(log->user_data_erase_counts.minimum));
    printf("User Data Erase Counts (Maximum)             : %"PRIu32"\n",
        le32_to_cpu(log->user_data_erase_counts.maximum));
    printf("Thermal Throttling Status (Current Status)   : %s\n",
        current_thermal_status_to_string(log->thermal_status.current_status));
    printf("Thermal Throttling Status (Number of Events) : %"PRIu8"\n",
        log->thermal_status.num_events);
    printf("PCIe Correctable Error Count                 : %"PRIu64"\n",
        le64_to_cpu(log->pcie_correctable_error_count));
    printf("Incomplete Shutdowns                         : %"PRIu32"\n",
        le32_to_cpu(log->incomplete_shutdowns));
    printf("%% Free Blocks                                : %"PRIu8"%%\n",
        log->percent_free_blocks);
    printf("Capacitor Health                             : %"PRIu16"%%\n",
        le16_to_cpu(log->capacitor_health));
    printf("Unaligned IO                                 : %"PRIu64"\n",
        le64_to_cpu(log->unaligned_io));
    printf("Security Version Number                      : %"PRIu64"\n",
        le64_to_cpu(log->security_version_number));
    printf("NUSE                                         : %"PRIu64"\n",
        le64_to_cpu(log->nuse));
    printf("PLP Start Count                              : %'.0Lf\n",
        int128_to_double(log->plp_start_count));
    printf("Endurance Estimate                           : %'.0Lf\n",
        int128_to_double(log->endurance_estimate));
    printf("Log Page Version                             : %"PRIu16"\n",
        le16_to_cpu(log->log_page_version));
    
    memset(log_page_guid, 0, sizeof(log_page_guid_buf));
    log_page_guid += sprintf(log_page_guid, "0x");
    for (i = 0; i < sizeof(log->log_page_guid); i++)
        log_page_guid += sprintf(log_page_guid, "%x", log->log_page_guid[15 - i]);

    printf("Log Page GUID                                : %s\n", log_page_guid_buf);
    printf("\n\n");
}

void print_fadu_cloud_attrs_log(struct fadu_cloud_attrs_log *log, enum nvme_print_flags flags)
{
    if (flags & BINARY)
        return d_raw((unsigned char *)log, sizeof(*log));
    else if (flags & JSON)
        return print_fadu_cloud_attrs_log_json(log);

    print_fadu_cloud_attrs_log_normal(log);
}

static const char *commit_action_type_to_string(__u8 ca_type) {
    const char *ca_values[8] = { "000b", "001b", "010b", "011b", "100b", "101b", "110b", "111b" };

    return ca_values[ca_type & 7];
}

void print_fadu_fw_act_history_json(struct fadu_fw_act_history *history) {
	struct json_object *root;
    struct json_object *entry;
    struct json_array *entries;
    __u32 num_entries;
    struct fadu_fw_act_history_entry *history_entry;
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
    num_entries = le32_to_cpu(history->num_entries);

    for (i = 0; i < num_entries; i++) {
        history_entry = &history->entries[i];

        memset((void *) timestamp_buf, 0, 20);
        memset((void *) prev_fw_buf, 0, 9);
        memset((void *) new_fw_buf, 0, 9);
        memset((void *) ca_type_buf, 0, 8);
        memset((void *) result_buf, 0, 12);

        timestamp = le64_to_cpu(history_entry->timestamp) / 1000;
        hour = timestamp / 3600;
        min = (timestamp % 3600) / 60;
        sec = timestamp % 60;
        sprintf(timestamp_buf, "%"PRIu64":%02"PRIu8":%02"PRIu8"", hour, min, sec);

        memcpy(prev_fw_buf, (char *) &(history_entry->prev_fw), 8);
        memcpy(new_fw_buf, (char *) &(history_entry->new_fw), 8);

        sprintf(ca_type_buf, "%s", commit_action_type_to_string(history_entry->ca_type));
        
        if (history_entry->result == 0)
            sprintf(result_buf, "pass");
        else
            sprintf(result_buf, "fail #%"PRIu16"", le16_to_cpu(history_entry->result));

        entry = json_create_object();

        json_object_add_value_uint(entry, "firwmare_action_counter", 
            le16_to_cpu(history_entry->counter));
        json_object_add_value_string(entry, "power_on_hour", timestamp_buf);
        json_object_add_value_uint(entry, "power_cycle_count",
            le64_to_cpu(history_entry->power_cycle));
        json_object_add_value_string(entry, "previous_firmware", prev_fw_buf);
        json_object_add_value_string(entry, "new_firmware_activated", new_fw_buf);
        json_object_add_value_uint(entry, "slot_number", history_entry->slot);
        json_object_add_value_string(entry, "commit_action_type", ca_type_buf);
        json_object_add_value_string(entry, "result", result_buf);

        json_array_add_value_object(entries, entry);
    }

	json_object_add_value_array(root, "entries", entries);

    json_print_object(root, NULL);
    printf("\n");
    json_free_object(root);
}

void print_fadu_fw_act_history_normal(struct fadu_fw_act_history *history) {
    __u32 num_entries;
    struct fadu_fw_act_history_entry *history_entry;
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

    num_entries = le32_to_cpu(history->num_entries);

    for (i = 0; i < num_entries; i++) {
        history_entry = &history->entries[i];

        memset((void *)timestamp_buf, 0, 20);
        memset((void *)prev_fw_buf, 0, 9);
        memset((void *)new_fw_buf, 0, 9);
        memset((void *)ca_type_buf, 0, 8);

        timestamp = le64_to_cpu(history_entry->timestamp) / 1000;
        hour = timestamp / 3600;
        min = (timestamp % 3600) / 60;
        sec = timestamp % 60;
        sprintf(timestamp_buf, "%"PRIu64":%02"PRIu8":%02"PRIu8"", hour, min, sec);

        memcpy(prev_fw_buf, (char *) &(history_entry->prev_fw), 8);
        memcpy(new_fw_buf, (char *) &(history_entry->new_fw), 8);

        sprintf(ca_type_buf, "%s", commit_action_type_to_string(history_entry->ca_type));

        printf("%-10"PRIu16"  ", le16_to_cpu(history_entry->counter));
        printf("%-14s  ", timestamp_buf);
        printf("%-16"PRIu64"  ", le64_to_cpu(history_entry->power_cycle));
        printf("%-8s  ", prev_fw_buf);
        printf("%-9s  ", new_fw_buf);
        printf("%-6"PRIu8"  ", history_entry->slot);
        printf("%-6s  ", ca_type_buf);

        if (history_entry->result == 0)
            printf("pass\n");
        else
            printf("fail #%"PRIu16"\n", le16_to_cpu(history_entry->result));
    }
    printf("\n\n");
}

void print_fadu_fw_act_history(struct fadu_fw_act_history *history, enum nvme_print_flags flags)
{
    if (flags & BINARY)
        return d_raw((unsigned char *) history, sizeof(*history));
    else if (flags & JSON)
        return print_fadu_fw_act_history_json(history);

    print_fadu_fw_act_history_normal(history);
}

void print_fadu_drive_info_json(struct fadu_drive_info *info) {
    struct json_object *root;
    char hw_rev_buf[20];
    __u16 hw_rev_major, hw_rev_minor;

    root = json_create_object();

    memset((void *) hw_rev_buf, 0, 20);

    hw_rev_major = le32_to_cpu(info->hw_revision) / 10;
    hw_rev_minor = le32_to_cpu(info->hw_revision) % 10;

    sprintf(hw_rev_buf, "%"PRIu32".%"PRIu32, hw_rev_major, hw_rev_minor);

    json_object_add_value_string(root, "hw_revision", hw_rev_buf);
    json_object_add_value_uint(root, "ftl_unit_size", le32_to_cpu(info->ftl_unit_size));
    
    json_print_object(root, NULL);
    printf("\n");
    json_free_object(root);
}

void print_fadu_drive_info_normal(struct fadu_drive_info *info) {
    __u16 hw_rev_major, hw_rev_minor;

    hw_rev_major = le32_to_cpu(info->hw_revision) / 10;
    hw_rev_minor = le32_to_cpu(info->hw_revision) % 10;

    printf("HW Revision   : %"PRIu32".%"PRIu32"\n", hw_rev_major, hw_rev_minor);
    printf("FTL Unit Size : %"PRIu32"\n", le32_to_cpu(info->ftl_unit_size));
    printf("\n\n");
}

void print_fadu_drive_info(struct fadu_drive_info *info, enum nvme_print_flags flags)
{
    if (flags & BINARY)
        return d_raw((unsigned char *)info, sizeof(*info));
    else if (flags & JSON)
        return print_fadu_drive_info_json(info);

    print_fadu_drive_info_normal(info);
}

static const char *log_id_to_string(__u8 log_id)
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

		case FADU_LOG_SMART_CLOUD_ATTRIBUTES:
            return "FADU OCP SMART Cloud Attributes Log ID";
		case FADU_LOG_ERROR_RECOVERY:
            return "FADU OCP Log Error Recovery Log ID";
		case FADU_LOG_FW_ACTIVATE_HISTORY:
            return "FADU OCP FW Activation History Log ID";

		default:
            return "FADU Vendor Unique Log ID";
	}
}

void print_fadu_log_page_directory_json(struct fadu_log_page_directory *dir) {
	struct json_object *root;
    struct json_object *entry;
    struct json_array *entries;
    __u32 num_log_ids;
    __u8  log_id;
    int i;

    root = json_create_object();
    entries = json_create_array();
    num_log_ids = le32_to_cpu(dir->num_log_ids);

    for (i = 0; i < num_log_ids; i++) {
        entry = json_create_object();
        log_id = dir->log_ids[i];

        json_object_add_value_uint(entry, "log_id", log_id);
        json_object_add_value_string(entry, "description", log_id_to_string(log_id));

        json_array_add_value_object(entries, entry);
    }

	json_object_add_value_array(root, "directory", entries);

    json_print_object(root, NULL);
    printf("\n");
    json_free_object(root);
}

void print_fadu_log_page_directory_normal(struct fadu_log_page_directory *dir) {
    __u32 num_log_ids;
    __u8  log_id;
    int i;

    num_log_ids = le32_to_cpu(dir->num_log_ids);
    for (i = 0; i < num_log_ids; i++) {
        log_id = dir->log_ids[i];
        printf("0x%02X: %s\n", log_id, log_id_to_string(log_id));
    }
}

void print_fadu_log_page_directory(struct fadu_log_page_directory *dir, enum nvme_print_flags flags)
{
    if (flags & BINARY)
        return d_raw((unsigned char *) dir, sizeof(*dir));
    else if (flags & JSON)
        return print_fadu_log_page_directory_json(dir);

    print_fadu_log_page_directory_normal(dir);
}

static int fadu_vs_smart_add_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
    struct fadu_cloud_attrs_log log;
	const char *desc ="Retrieve SMART Cloud Attributes log for the given device.";
    const char *raw = "output in binary format";
    int flags, err, fd;
    __u8 log_page_guid[16] = {
        0xC5, 0xAF, 0x10, 0x28, 0xEA, 0xBF, 0xF2, 0xA4,
        0x9C, 0x4F, 0x6F, 0x7C, 0xC9, 0x14, 0xD5, 0xAF
    };

	struct config {
		char *output_format;
        int raw_binary;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
        OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0) {
        fprintf(stderr, "[ERROR] invalid output format: %s\n", cfg.output_format);
        goto close_fd;
    }
    if (cfg.raw_binary) {
        flags = BINARY;
    }

	err = nvme_get_log(fd, NVME_NSID_ALL, FADU_LOG_SMART_CLOUD_ATTRIBUTES,
        false, sizeof(log), &log);
	if (!err) {
        if (invalid_log_page_guid(log_page_guid, log.log_page_guid))
            fprintf(stderr, "invalid log page format\n");
        else
            print_fadu_cloud_attrs_log(&log, flags);
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

static int fadu_vs_internal_log(int argc, char **argv, struct command *cmd, struct plugin *plugin) { return 0; }

static int fadu_vs_fw_activate_history(int argc, char **argv, struct command *cmd, struct plugin *plugin) { 
    struct fadu_fw_act_history history;
	const char *desc ="Retrieve FW activate history table for the given device.";
    const char *raw = "output in binary format";
    int flags, err, fd;
    __u8 log_page_guid[16] = {
        0x6D, 0x79, 0x9A, 0x76, 0xB4, 0xDA, 0xF6, 0xA3,
        0xE2, 0x4D, 0xB2, 0x8A, 0xAC, 0xF3, 0x1C, 0xD1
    };

	struct config {
		char *output_format;
        int raw_binary;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
        OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0) {
        fprintf(stderr, "[ERROR] invalid output format: %s\n", cfg.output_format);
		goto close_fd;
    }
    if (cfg.raw_binary) {
        flags = BINARY;
    }

	err = nvme_get_log(fd, NVME_NSID_ALL, FADU_LOG_FW_ACTIVATE_HISTORY,
        false, sizeof(history), &history);
	if (!err) {
        if (invalid_log_page_guid(log_page_guid, history.log_page_guid))
            fprintf(stderr, "invalid log page format\n");
        else
            print_fadu_fw_act_history(&history, flags);
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

static int fadu_vs_drive_info(int argc, char **argv, struct command *cmd, struct plugin *plugin) {
    struct fadu_drive_info info;
	const char *desc ="Retrieve drive information for the given device.";
    const char *raw = "output in binary format";
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
        OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0) {
        fprintf(stderr, "[ERROR] invalid output format: %s\n", cfg.output_format);
		goto close_fd;
    }
    if (cfg.raw_binary) {
        flags = BINARY;
    }

    data_len = sizeof(info);
    err = nvme_passthru(fd, NVME_IOCTL_ADMIN_CMD, FADU_NVME_ADMIN_VUC_OPCODE, 0, 0,
        0, FADU_VUC_SUBOPCODE_VS_DRIVE_INFO, 0, get_num_dwords(data_len), 0, 0, 0, 0, 0,
        data_len, &info, 0, NULL, 0, NULL);
	if (!err)
		print_fadu_drive_info(&info, flags);
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

static int fadu_log_page_directory(int argc, char **argv, struct command *cmd, struct plugin *plugin) {
    struct fadu_log_page_directory dir;
	const char *desc ="Retrieve log page directory for the given device.";
    const char *raw = "output in binary format";
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
        OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_output_format(cfg.output_format);
	if (flags < 0) {
        fprintf(stderr, "[ERROR] invalid output format: %s\n", cfg.output_format);
		goto close_fd;
    }
    if (cfg.raw_binary) {
        flags = BINARY;
    }

    data_len = sizeof(dir);
    err = nvme_passthru(fd, NVME_IOCTL_ADMIN_CMD, FADU_NVME_ADMIN_VUC_OPCODE, 0, 0,
        0, FADU_VUC_SUBOPCODE_LOG_PAGE_DIR, 0, get_num_dwords(data_len), 0, 0, 0, 0, 0,
        data_len, &dir, 0, NULL, 0, NULL);
	if (!err)
		print_fadu_log_page_directory(&dir, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		perror("log-page-directory");

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}

static int fadu_cloud_ssd_plugin_version(int argc, char **argv, struct command *cmd, struct plugin *plugin) {
    printf("cloud ssd plugin version: %d.%d\n", plugin_version_major, plugin_version_minor);
    return 0;
}

static int fadu_vs_telemetry_controller_option(int argc, char **argv, struct command *cmd, struct plugin *plugin) {
	const char *desc = "Control controller-initiated telemetry log page for the given device.";
    const char *option = "Option: enable|disable|status";
	int flags;
	int err, fd;
    __u32 data_buf;
    __u32 subopcode;
    __u32 mode = 0;
    __u32 data_len = 0;
    __u32 *data = NULL;
    __u32 timeout_ms = 0;

	struct config {
		char *option;
	};

	struct config cfg = {
		.option = "status",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("option", 'o', &cfg.option, option),
		OPT_END()
	};

	err = fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		goto ret;

	err = flags = validate_fadu_ctrl_option(cfg.option);
	if (flags == -EINVAL) {
        fprintf(stderr, "ERROR: invalid option: %s\n", cfg.option);
        goto close_fd;
    }

    if (flags == FADU_CTRL_OPTION_STATUS) {
        subopcode = FADU_VUC_SUBOPCODE_GET_TELEMETRY_MODE;
        data = &data_buf;
        data_len = sizeof(data_buf);
        timeout_ms = 1;
    } else {
        subopcode = FADU_VUC_SUBOPCODE_SET_TELEMETRY_MODE;
        mode = flags == FADU_CTRL_OPTION_ENABLE ? 1 : 0;
    }

    err = nvme_passthru(fd, NVME_IOCTL_ADMIN_CMD, FADU_NVME_ADMIN_VUC_OPCODE, 0, 0,
        0, subopcode, 0, get_num_dwords(data_len), 0, mode, 0, 0, 0,
        data_len, data, 0, NULL, timeout_ms, NULL);
	if (!err) {
        if (flags == FADU_CTRL_OPTION_STATUS)
            printf("%s\n", data_buf ? "enabled" : "disabled");
        else
            printf("%s successfully\n", flags == FADU_CTRL_OPTION_ENABLE ? "enabled" : "disabled");
    } else if (err > 0) {
        nvme_show_status(err);
    } else {
        perror("log-page-directory");
    }

close_fd:
	close(fd);
ret:
	return nvme_status_to_errno(err, false);
}
