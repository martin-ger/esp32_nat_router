#pragma once

#include "sdkconfig.h"

#if CONFIG_REPEATER_MODE

#include <stdint.h>
#include <stdbool.h>

#define REPEATER_FDB_SIZE           32
#define REPEATER_FDB_DEFAULT_TTL_S  600

#define REPEATER_XID_MAP_SIZE       16
#define REPEATER_XID_TTL_S          30

#endif
