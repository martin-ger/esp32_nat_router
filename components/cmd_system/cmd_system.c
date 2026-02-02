/* Console example — various system commands

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "esp_log.h"
#include "esp_console.h"
#include "esp_system.h"
#include "nvs.h"
#include "router_globals.h"
#include "esp_sleep.h"
#include "esp_flash.h"
#include "esp_chip_info.h"
#include "driver/rtc_io.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "argtable3/argtable3.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "cmd_system.h"
#include "sdkconfig.h"

#ifdef CONFIG_FREERTOS_USE_STATS_FORMATTING_FUNCTIONS
#define WITH_TASKS_INFO 1
#endif

static const char *TAG = "cmd_system";

void load_log_level(void)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs);
    if (err == ESP_OK) {
        uint8_t level = ESP_LOG_INFO;  // Default
        if (nvs_get_u8(nvs, "log_level", &level) == ESP_OK) {
            if (level <= ESP_LOG_VERBOSE) {
                esp_log_level_set("*", (esp_log_level_t)level);
                ESP_LOGI(TAG, "Log level loaded from NVS: %d", level);
            }
        }
        nvs_close(nvs);
    }
}

static void register_heap(void);
static void register_version(void);
static void register_restart(void);
static void register_factory_reset(void);
static void register_deep_sleep(void);
static void register_light_sleep(void);
static void register_log_level(void);
#if WITH_TASKS_INFO
static void register_tasks(void);
#endif

void register_system(void)
{
    register_heap();
    register_version();
    register_restart();
    register_factory_reset();
    register_deep_sleep();
    register_light_sleep();
    register_log_level();
#if WITH_TASKS_INFO
    register_tasks();
#endif
}

/* 'version' command */
static const char* get_chip_model_name(esp_chip_model_t model)
{
    switch (model) {
        case CHIP_ESP32:   return "ESP32";
        case CHIP_ESP32S2: return "ESP32-S2";
        case CHIP_ESP32S3: return "ESP32-S3";
        case CHIP_ESP32C3: return "ESP32-C3";
        case CHIP_ESP32C2: return "ESP32-C2";
        case CHIP_ESP32C6: return "ESP32-C6";
        case CHIP_ESP32H2: return "ESP32-H2";
        default:           return "Unknown";
    }
}

static int get_version(int argc, char **argv)
{
    esp_chip_info_t info;
    esp_chip_info(&info);
    uint32_t size_flash_chip;
    esp_flash_get_size(NULL, &size_flash_chip);
    printf("IDF Version:%s\r\n", esp_get_idf_version());
    printf("Chip info:\r\n");
    printf("\tmodel:%s\r\n", get_chip_model_name(info.model));
    printf("\tcores:%d\r\n", info.cores);
    printf("\tfeature:%s%s%s%s%lu%s\r\n",
           info.features & CHIP_FEATURE_WIFI_BGN ? "/802.11bgn" : "",
           info.features & CHIP_FEATURE_BLE ? "/BLE" : "",
           info.features & CHIP_FEATURE_BT ? "/BT" : "",
           info.features & CHIP_FEATURE_EMB_FLASH ? "/Embedded-Flash:" : "/External-Flash:",
           size_flash_chip / (1024 * 1024), " MB");
    printf("\trevision number:%d\r\n", info.revision);
    return 0;
}

static void register_version(void)
{
    const esp_console_cmd_t cmd = {
        .command = "version",
        .help = "Get version of chip and SDK",
        .hint = NULL,
        .func = &get_version,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/** 'restart' command restarts the program */

static int restart(int argc, char **argv)
{
    ESP_LOGI(TAG, "Restarting");
    esp_restart();
}

static void register_restart(void)
{
    const esp_console_cmd_t cmd = {
        .command = "restart",
        .help = "Software reset of the chip",
        .hint = NULL,
        .func = &restart,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/** 'factory_reset' command erases all settings and restarts */

static int factory_reset(int argc, char **argv)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err == ESP_OK) {
        err = nvs_erase_all(nvs);
        if (err == ESP_OK) {
            err = nvs_commit(nvs);
        }
        nvs_close(nvs);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to erase NVS namespace: %s", esp_err_to_name(err));
        return 1;
    }
    ESP_LOGI(TAG, "NVS namespace '%s' erased, restarting...", PARAM_NAMESPACE);
    esp_restart();
    return 0; // Never reached
}

static void register_factory_reset(void)
{
    const esp_console_cmd_t cmd = {
        .command = "factory_reset",
        .help = "Erase all settings (NVS namespace '" PARAM_NAMESPACE "') and restart",
        .hint = NULL,
        .func = &factory_reset,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/** 'heap' command prints available heap memory */

static int heap_mem(int argc, char **argv)
{
    printf("Current heap size: %lu (minimal: %u)\n", esp_get_free_heap_size(), 
        heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT));
    return 0;
}

static void register_heap(void)
{
    const esp_console_cmd_t cmd = {
        .command = "heap",
        .help = "Get the current amd min size of free heap memory",
        .hint = NULL,
        .func = &heap_mem,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/** 'tasks' command prints the list of tasks and related information */
#if WITH_TASKS_INFO

static int tasks_info(int argc, char **argv)
{
    const size_t bytes_per_task = 40; /* see vTaskList description */
    char *task_list_buffer = malloc(uxTaskGetNumberOfTasks() * bytes_per_task);
    if (task_list_buffer == NULL) {
        ESP_LOGE(TAG, "failed to allocate buffer for vTaskList output");
        return 1;
    }
    fputs("Task Name\tStatus\tPrio\tHWM\tTask#", stdout);
#ifdef CONFIG_FREERTOS_VTASKLIST_INCLUDE_COREID
    fputs("\tAffinity", stdout);
#endif
    fputs("\n", stdout);
    vTaskList(task_list_buffer);
    fputs(task_list_buffer, stdout);
    free(task_list_buffer);
    return 0;
}

static void register_tasks(void)
{
    const esp_console_cmd_t cmd = {
        .command = "tasks",
        .help = "Get information about running tasks",
        .hint = NULL,
        .func = &tasks_info,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

#endif // WITH_TASKS_INFO

/** 'deep_sleep' command puts the chip into deep sleep mode */

static struct {
    struct arg_int *wakeup_time;
    struct arg_int *wakeup_gpio_num;
    struct arg_int *wakeup_gpio_level;
    struct arg_end *end;
} deep_sleep_args;


static int deep_sleep(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **) &deep_sleep_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, deep_sleep_args.end, argv[0]);
        return 1;
    }
    if (deep_sleep_args.wakeup_time->count) {
        uint64_t timeout = 1000ULL * deep_sleep_args.wakeup_time->ival[0];
        ESP_LOGI(TAG, "Enabling timer wakeup, timeout=%lluus", timeout);
        ESP_ERROR_CHECK( esp_sleep_enable_timer_wakeup(timeout) );
    }
    if (deep_sleep_args.wakeup_gpio_num->count) {
        int io_num = deep_sleep_args.wakeup_gpio_num->ival[0];
        if (!GPIO_IS_VALID_GPIO(io_num)) {
            ESP_LOGE(TAG, "GPIO %d is not a valid GPIO", io_num);
            return 1;
        }
        int level = 0;
        if (deep_sleep_args.wakeup_gpio_level->count) {
            level = deep_sleep_args.wakeup_gpio_level->ival[0];
            if (level != 0 && level != 1) {
                ESP_LOGE(TAG, "Invalid wakeup level: %d", level);
                return 1;
            }
        }
        ESP_LOGI(TAG, "Enabling wakeup on GPIO%d, wakeup on %s level",
                 io_num, level ? "HIGH" : "LOW");

        #if defined(CONFIG_IDF_TARGET_ESP32) || defined(CONFIG_IDF_TARGET_ESP32S2)
            ESP_ERROR_CHECK( esp_sleep_enable_ext1_wakeup(1ULL << io_num, level) );
        #endif
    }
    #if defined(CONFIG_IDF_TARGET_ESP32) || defined(CONFIG_IDF_TARGET_ESP32S2)
        rtc_gpio_isolate(GPIO_NUM_12);
    #endif
    esp_deep_sleep_start();
}

static void register_deep_sleep(void)
{
    deep_sleep_args.wakeup_time =
        arg_int0("t", "time", "<t>", "Wake up time, ms");
    deep_sleep_args.wakeup_gpio_num =
        arg_int0(NULL, "io", "<n>",
                 "If specified, wakeup using GPIO with given number");
    deep_sleep_args.wakeup_gpio_level =
        arg_int0(NULL, "io_level", "<0|1>", "GPIO level to trigger wakeup");
    deep_sleep_args.end = arg_end(3);

    const esp_console_cmd_t cmd = {
        .command = "deep_sleep",
        .help = "Enter deep sleep mode. "
        "Two wakeup modes are supported: timer and GPIO. "
        "If no wakeup option is specified, will sleep indefinitely.",
        .hint = NULL,
        .func = &deep_sleep,
        .argtable = &deep_sleep_args
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/** 'light_sleep' command puts the chip into light sleep mode */

static struct {
    struct arg_int *wakeup_time;
    struct arg_int *wakeup_gpio_num;
    struct arg_int *wakeup_gpio_level;
    struct arg_end *end;
} light_sleep_args;

static int light_sleep(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **) &light_sleep_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, light_sleep_args.end, argv[0]);
        return 1;
    }
    esp_sleep_disable_wakeup_source(ESP_SLEEP_WAKEUP_ALL);
    if (light_sleep_args.wakeup_time->count) {
        uint64_t timeout = 1000ULL * light_sleep_args.wakeup_time->ival[0];
        ESP_LOGI(TAG, "Enabling timer wakeup, timeout=%lluus", timeout);
        ESP_ERROR_CHECK( esp_sleep_enable_timer_wakeup(timeout) );
    }
    int io_count = light_sleep_args.wakeup_gpio_num->count;
    if (io_count != light_sleep_args.wakeup_gpio_level->count) {
        ESP_LOGE(TAG, "Should have same number of 'io' and 'io_level' arguments");
        return 1;
    }
    for (int i = 0; i < io_count; ++i) {
        int io_num = light_sleep_args.wakeup_gpio_num->ival[i];
        int level = light_sleep_args.wakeup_gpio_level->ival[i];
        if (level != 0 && level != 1) {
            ESP_LOGE(TAG, "Invalid wakeup level: %d", level);
            return 1;
        }
        ESP_LOGI(TAG, "Enabling wakeup on GPIO%d, wakeup on %s level",
                 io_num, level ? "HIGH" : "LOW");

        ESP_ERROR_CHECK( gpio_wakeup_enable(io_num, level ? GPIO_INTR_HIGH_LEVEL : GPIO_INTR_LOW_LEVEL) );
    }
    if (io_count > 0) {
        ESP_ERROR_CHECK( esp_sleep_enable_gpio_wakeup() );
    }
    if (CONFIG_ESP_CONSOLE_UART_NUM <= UART_NUM_1) {
        ESP_LOGI(TAG, "Enabling UART wakeup (press ENTER to exit light sleep)");
        ESP_ERROR_CHECK( uart_set_wakeup_threshold(CONFIG_ESP_CONSOLE_UART_NUM, 3) );
        ESP_ERROR_CHECK( esp_sleep_enable_uart_wakeup(CONFIG_ESP_CONSOLE_UART_NUM) );
    }
    fflush(stdout);
    uart_wait_tx_idle_polling(CONFIG_ESP_CONSOLE_UART_NUM);
    esp_light_sleep_start();
    esp_sleep_wakeup_cause_t cause = esp_sleep_get_wakeup_cause();
    const char *cause_str;
    switch (cause) {
    case ESP_SLEEP_WAKEUP_GPIO:
        cause_str = "GPIO";
        break;
    case ESP_SLEEP_WAKEUP_UART:
        cause_str = "UART";
        break;
    case ESP_SLEEP_WAKEUP_TIMER:
        cause_str = "timer";
        break;
    default:
        cause_str = "unknown";
        printf("%d\n", cause);
    }
    ESP_LOGI(TAG, "Woke up from: %s", cause_str);
    return 0;
}

static void register_light_sleep(void)
{
    light_sleep_args.wakeup_time =
        arg_int0("t", "time", "<t>", "Wake up time, ms");
    light_sleep_args.wakeup_gpio_num =
        arg_intn(NULL, "io", "<n>", 0, 8,
                 "If specified, wakeup using GPIO with given number");
    light_sleep_args.wakeup_gpio_level =
        arg_intn(NULL, "io_level", "<0|1>", 0, 8, "GPIO level to trigger wakeup");
    light_sleep_args.end = arg_end(3);

    const esp_console_cmd_t cmd = {
        .command = "light_sleep",
        .help = "Enter light sleep mode. "
        "Two wakeup modes are supported: timer and GPIO. "
        "Multiple GPIO pins can be specified using pairs of "
        "'io' and 'io_level' arguments. "
        "Will also wake up on UART input.",
        .hint = NULL,
        .func = &light_sleep,
        .argtable = &light_sleep_args
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/** 'log_level' command sets the logging level */

static struct {
    struct arg_str *level;
    struct arg_str *tag;
    struct arg_end *end;
} log_level_args;

static esp_log_level_t parse_log_level(const char *level_str)
{
    if (strcasecmp(level_str, "none") == 0 || strcmp(level_str, "0") == 0) {
        return ESP_LOG_NONE;
    } else if (strcasecmp(level_str, "error") == 0 || strcmp(level_str, "1") == 0) {
        return ESP_LOG_ERROR;
    } else if (strcasecmp(level_str, "warn") == 0 || strcmp(level_str, "2") == 0) {
        return ESP_LOG_WARN;
    } else if (strcasecmp(level_str, "info") == 0 || strcmp(level_str, "3") == 0) {
        return ESP_LOG_INFO;
    } else if (strcasecmp(level_str, "debug") == 0 || strcmp(level_str, "4") == 0) {
        return ESP_LOG_DEBUG;
    } else if (strcasecmp(level_str, "verbose") == 0 || strcmp(level_str, "5") == 0) {
        return ESP_LOG_VERBOSE;
    }
    return (esp_log_level_t)-1;  // Invalid
}

static const char* log_level_to_str(esp_log_level_t level)
{
    switch (level) {
        case ESP_LOG_NONE:    return "NONE";
        case ESP_LOG_ERROR:   return "ERROR";
        case ESP_LOG_WARN:    return "WARN";
        case ESP_LOG_INFO:    return "INFO";
        case ESP_LOG_DEBUG:   return "DEBUG";
        case ESP_LOG_VERBOSE: return "VERBOSE";
        default:              return "UNKNOWN";
    }
}

static int log_level_cmd(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **) &log_level_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, log_level_args.end, argv[0]);
        return 1;
    }

    if (log_level_args.level->count == 0) {
        // No level specified, show current level and usage
        nvs_handle_t nvs;
        uint8_t saved_level = ESP_LOG_INFO;
        if (nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs) == ESP_OK) {
            nvs_get_u8(nvs, "log_level", &saved_level);
            nvs_close(nvs);
        }
        printf("Current default log level: %s (%d)\n", log_level_to_str(saved_level), saved_level);
        printf("Log levels: none(0), error(1), warn(2), info(3), debug(4), verbose(5)\n");
        printf("Usage: log_level <level> [-t <tag>]\n");
        printf("  Without -t: sets and saves default level for all tags\n");
        printf("  With -t: sets level for specific tag only (not saved)\n");
        return 0;
    }

    const char *level_str = log_level_args.level->sval[0];
    esp_log_level_t level = parse_log_level(level_str);

    if ((int)level == -1) {
        printf("Invalid log level: %s\n", level_str);
        printf("Valid levels: none, error, warn, info, debug, verbose (or 0-5)\n");
        return 1;
    }

    if (log_level_args.tag->count > 0) {
        // Set level for specific tag (not persisted)
        const char *tag = log_level_args.tag->sval[0];
        esp_log_level_set(tag, level);
        printf("Log level for '%s' set to %s (%d) (not saved)\n", tag, log_level_to_str(level), level);
    } else {
        // Set default level for all tags and save to NVS
        esp_log_level_set("*", level);

        nvs_handle_t nvs;
        esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
        if (err == ESP_OK) {
            nvs_set_u8(nvs, "log_level", (uint8_t)level);
            nvs_commit(nvs);
            nvs_close(nvs);
            printf("Default log level set to %s (%d) and saved\n", log_level_to_str(level), level);
        } else {
            printf("Default log level set to %s (%d) (failed to save: %s)\n",
                   log_level_to_str(level), level, esp_err_to_name(err));
        }
    }

    return 0;
}

static void register_log_level(void)
{
    log_level_args.level = arg_str0(NULL, NULL, "<level>", "Log level: none/error/warn/info/debug/verbose (or 0-5)");
    log_level_args.tag = arg_str0("t", "tag", "<tag>", "Set level for specific tag only");
    log_level_args.end = arg_end(2);

    const esp_console_cmd_t cmd = {
        .command = "log_level",
        .help = "Get/set logging level. Without arguments shows usage. "
                "Use -t to set level for a specific tag.",
        .hint = NULL,
        .func = &log_level_cmd,
        .argtable = &log_level_args
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

