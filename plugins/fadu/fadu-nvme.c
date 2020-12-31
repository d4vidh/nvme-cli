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
    FADU_LOG_SMART_CLOUD_ATTRIBUTES = 0xC0,
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
		OPT_FMT("output-format",   'o', &cfg.output_format,  output_format_no_binary),
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
static int fadu_vs_fw_activate_history(int argc, char **argv, struct command *cmd, struct plugin *plugin) { return 0; }
static int fadu_vs_drive_info(int argc, char **argv, struct command *cmd, struct plugin *plugin) { return 0; }
static int fadu_clear_pcie_correctable_errors(int argc, char **argv, struct command *cmd, struct plugin *plugin) { return 0; }
static int fadu_clear_fw_activate_history(int argc, char **argv, struct command *cmd, struct plugin *plugin) { return 0; }
static int fadu_log_page_directory(int argc, char **argv, struct command *cmd, struct plugin *plugin) { return 0; }

static int fadu_cloud_ssd_plugin_version(int argc, char **argv, struct command *cmd, struct plugin *plugin) {
    printf("cloud ssd plugin version: %d.%d\n", plugin_version_major, plugin_version_minor);
    return 0;
}

static int fadu_telemetry_controller_option(int argc, char **argv, struct command *cmd, struct plugin *plugin) { return 0; }
