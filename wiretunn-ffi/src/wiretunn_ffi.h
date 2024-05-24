#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Create and run a new Wiretunn App, this function will blocks current thread.
 */
int32_t wiretunn_app_run(uint8_t runtime_id, const char *s);

/**
 * Notify the Wiretunn App shutdown
 */
void wiretunn_app_shutdown(uint8_t runtime_id);
