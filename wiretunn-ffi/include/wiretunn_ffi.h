#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

struct tunnel; // This corresponds to the Rust type

/**
 * Return FFI library version
 */
char *wiretunn_version(void);

/**
 * Create and run a new Wiretunn App, this function will blocks current thread.
 */
int32_t wiretunn_app_run(uint8_t runtime_id, const char *s);

/**
 * Notify the Wiretunn App shutdown
 */
void wiretunn_app_shutdown(uint8_t runtime_id);

/**
 * Allocate a new tunnel, return NULL on failure.
 */
struct tunnel *new_tunnel(const char *s);

/**
 * Drops the Tunnel object
 */
void tunnel_free(struct tunnel *);
