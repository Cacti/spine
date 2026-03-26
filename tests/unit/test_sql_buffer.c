#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

/* Mocking necessary definitions to avoid linking the entire spine project for a unit test */
#define STANDALONE_TEST
#define SPINE_LOG(x) do { printf x; printf("\n"); } while(0)
#define MALLOC_OR_DIE(dst, type, size, reason) \
	do { \
		if (((dst) = (type *)malloc(size)) == NULL) { \
			printf("FATAL: malloc() failed during allocation of %s\n", reason); \
			exit(1); \
		} \
	} while (0)

#define STRDUP_OR_DIE(dst, src, reason) \
	do { \
		if (((dst) = strdup(src)) == NULL) { \
			printf("FATAL: malloc() failed during strdup() for %s\n", reason); \
			exit(1); \
		} \
	} while (0)

/* Minimal mocks for sql.h types */
typedef void MYSQL;
typedef void MYSQL_RES;
typedef void pool_t;

#include "sql.h"

/* Simplified implementation of sql_buffer for unit testing */
int sql_buffer_init(sql_buffer_t *sb, size_t initial_capacity) {
	if (sb == NULL || initial_capacity == 0 || initial_capacity > SQL_MAX_BUFFER_CAPACITY) {
		return -1;
	}

	sb->buffer = (char *)malloc(initial_capacity);
	if (sb->buffer == NULL) {
		sb->capacity = 0;
		sb->length   = 0;
		return -1;
	}

	sb->capacity  = initial_capacity;
	sb->length    = 0;
	sb->buffer[0] = '\0';

	return 0;
}

void sql_buffer_free(sql_buffer_t *sb) {
	if (sb != NULL && sb->buffer != NULL) {
		free(sb->buffer);
		sb->buffer   = NULL;
		sb->capacity = 0;
		sb->length   = 0;
	}
}

void sql_buffer_truncate(sql_buffer_t *sb, size_t length) {
	if (sb != NULL && sb->buffer != NULL && length <= sb->length) {
		sb->buffer[length] = '\0';
		sb->length = length;
	}
}

int sql_buffer_append(sql_buffer_t *sb, const char *format, ...) {
	va_list args;
	va_list args_copy;
	size_t  available;
	size_t  required_capacity;
	size_t  new_capacity;
	char    *new_buffer;
	int     written;

	if (sb == NULL || sb->buffer == NULL || format == NULL) return -1;
	if (sb->length >= sb->capacity) return -1;

	available = sb->capacity - sb->length;

	va_start(args, format);
	va_copy(args_copy, args);

	written = vsnprintf(sb->buffer + sb->length, available, format, args);
	va_end(args);

	if (written < 0) {
		va_end(args_copy);
		return -1;
	}

	if ((size_t)written >= available) {
		required_capacity = sb->length + (size_t)written + 1;
		if (required_capacity > SQL_MAX_BUFFER_CAPACITY) {
			va_end(args_copy);
			return -1;
		}

		new_capacity = sb->capacity;
		while (new_capacity < required_capacity) new_capacity *= 2;

		new_buffer = (char *)realloc(sb->buffer, new_capacity);
		if (new_buffer == NULL) {
			va_end(args_copy);
			return -1;
		}

		sb->buffer   = new_buffer;
		sb->capacity = new_capacity;

		written = vsnprintf(sb->buffer + sb->length, sb->capacity - sb->length, format, args_copy);
	}
	va_end(args_copy);

	sb->length += (size_t)written;
	return 0;
}

void test_sql_buffer_init() {
    sql_buffer_t sb;
    int ret = sql_buffer_init(&sb, 1024);
    assert(ret == 0);
    assert(sb.capacity == 1024);
    assert(sb.length == 0);
    assert(sb.buffer[0] == '\0');
    sql_buffer_free(&sb);
}

void test_sql_buffer_append() {
    sql_buffer_t sb;
    sql_buffer_init(&sb, 16);
    
    int ret = sql_buffer_append(&sb, "%s", "hello");
    assert(ret == 0);
    assert(sb.length == 5);
    assert(strcmp(sb.buffer, "hello") == 0);

    /* Test reallocation trigger */
    ret = sql_buffer_append(&sb, " world. This is a longer string that will force a reallocation.");
    assert(ret == 0);
    assert(sb.length > 15);
    assert(sb.capacity > 16);
    
    sql_buffer_free(&sb);
}

void test_sql_buffer_truncate() {
    sql_buffer_t sb;
    sql_buffer_init(&sb, 100);
    sql_buffer_append(&sb, "0123456789");
    
    sql_buffer_truncate(&sb, 5);
    assert(sb.length == 5);
    assert(strcmp(sb.buffer, "01234") == 0);
    
    sql_buffer_free(&sb);
}

int main() {
    printf("Running sql_buffer tests...\n");
    test_sql_buffer_init();
    test_sql_buffer_append();
    test_sql_buffer_truncate();
    printf("All sql_buffer tests passed.\n");
    return 0;
}
