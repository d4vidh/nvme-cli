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

static const int plugin_version_major = 1;
static const int plugin_version_minor = 0;

static int fadu_vs_smart_add_log(int argc, char **argv, struct command *cmd, struct plugin *plugin) { return 0; }
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
