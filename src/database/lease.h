/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifndef SPINE_DB_LEASE_H
#define SPINE_DB_LEASE_H
#include "internal/spine_types.h"

typedef struct {
	pool_t *connection;
	size_t index;
	uint64_t generation;
	int type;
} db_lease_t;

/* One owner per connection array. Slots are borrowed; its mutex and lease
 * generations are owned until no borrower remains. Leases belong to their
 * acquiring thread and cannot release a slot recycled for a later borrower. */
int db_pool_ownership_init(pool_t *slots, size_t count);
int db_pool_ownership_destroy(pool_t *slots);
size_t db_pool_owned_size(const pool_t *slots);
pool_t *db_pool_take_owned(pool_t *slots, db_lease_t *lease);
int db_pool_return_owned(pool_t *slots, db_lease_t *lease);
bool db_acquire_lease(int type, db_lease_t *lease);
bool db_release_lease(db_lease_t *lease);
#endif
