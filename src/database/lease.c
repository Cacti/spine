/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "database/lease.h"
#include <limits.h>

typedef struct db_pool_ownership {
	pool_t *slots;
	size_t count;
	pthread_mutex_t mutex;
} db_pool_ownership_t;

size_t db_pool_owned_size(const pool_t *slots) {
	if (slots == NULL || slots[0].ownership == NULL || slots[0].ownership->slots != slots) return 0;
	return slots[0].ownership->count;
}

int db_pool_ownership_init(pool_t *slots, size_t count) {
	db_pool_ownership_t *owner;
	size_t index;
	int error;
	if (slots == NULL || count == 0 || count > INT_MAX || slots[0].ownership != NULL) return EINVAL;
	owner = calloc(1, sizeof(*owner));
	if (owner == NULL) return ENOMEM;
	error = pthread_mutex_init(&owner->mutex, NULL);
	if (error != 0) {
		free(owner);
		return error;
	}
	owner->slots = slots;
	owner->count = count;
	for (index = 0; index < count; index++) {
		slots[index].ownership = owner;
		slots[index].id = (int) index;
		slots[index].generation = 0;
		slots[index].leased = false;
	}
	return 0;
}

int db_pool_ownership_destroy(pool_t *slots) {
	db_pool_ownership_t *owner;
	size_t index;
	int error;
	if (slots == NULL || slots[0].ownership == NULL) return EINVAL;
	owner = slots[0].ownership;
	if (owner->slots != slots) return EINVAL;
	for (index = 0; index < owner->count; index++) {
		if (slots[index].leased) return EBUSY;
	}
	/* Destruction belongs to the parent, after joins prevent new borrowers. */
	error = pthread_mutex_destroy(&owner->mutex);
	if (error != 0) return error;
	for (index = 0; index < owner->count; index++) slots[index].ownership = NULL;
	free(owner);
	return 0;
}

pool_t *db_pool_take_owned(pool_t *slots, db_lease_t *lease) {
	db_pool_ownership_t *owner;
	size_t index;
	pool_t *connection = NULL;
	if (slots == NULL || lease == NULL || lease->connection != NULL || slots[0].ownership == NULL) return NULL;
	owner = slots[0].ownership;
	if (owner->slots != slots) return NULL;
	pthread_mutex_lock(&owner->mutex);
	for (index = 0; index < owner->count; index++) {
		pool_t *slot = &slots[index];
		if (!slot->free || slot->leased || slot->generation == UINT64_MAX) continue;
		slot->generation++;
		slot->borrower = pthread_self();
		slot->leased = true;
		slot->free = FALSE;
		lease->connection = slot;
		lease->index = index;
		lease->generation = slot->generation;
		connection = slot;
		break;
	}
	pthread_mutex_unlock(&owner->mutex);
	return connection;
}

int db_pool_return_owned(pool_t *slots, db_lease_t *lease) {
	db_pool_ownership_t *owner;
	pool_t *slot;
	int error = 0;
	if (slots == NULL || lease == NULL || lease->connection == NULL || slots[0].ownership == NULL) return EINVAL;
	owner = slots[0].ownership;
	if (owner->slots != slots || lease->index >= owner->count) return EINVAL;
	slot = &slots[lease->index];
	if (lease->connection != slot) return EINVAL;
	pthread_mutex_lock(&owner->mutex);
	if (!slot->leased || slot->generation != lease->generation || !pthread_equal(slot->borrower, pthread_self())) {
		error = EPERM;
	} else {
		slot->leased = false;
		slot->free = TRUE;
		lease->connection = NULL;
	}
	pthread_mutex_unlock(&owner->mutex);
	return error;
}
