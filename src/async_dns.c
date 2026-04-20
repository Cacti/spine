#include "common.h"
#include "spine.h"
#include "async_dns.h"

#ifdef HAVE_CARES
#include <ares.h>

typedef struct async_dns_watcher async_dns_watcher_t;

struct spine_async_dns_runtime {
	uv_loop_t *loop;
	ares_channel channel;
	uv_timer_t timer;
	bool timer_initialized;
	bool timer_started;
	bool initialized;
	bool shutting_down;
	int close_refs;
	async_dns_watcher_t *watchers;
};

struct async_dns_watcher {
	spine_async_dns_runtime_t *runtime;
	ares_socket_t fd;
	uv_poll_t poll;
	bool closing;
	async_dns_watcher_t *next;
};

typedef struct {
	spine_async_dns_runtime_t *runtime;
	async_dns_cb callback;
	void *data;
	bool completed;
} async_dns_query_ctx_t;

static void spine_async_dns_free_addrinfo(struct addrinfo *res) {
	while (res != NULL) {
		struct addrinfo *next = res->ai_next;
		free(res->ai_addr);
		free(res->ai_canonname);
		free(res);
		res = next;
	}
}

static struct addrinfo *spine_async_dns_clone_first_addrinfo(const struct ares_addrinfo *result) {
	const struct ares_addrinfo_node *node;
	struct addrinfo *copy;

	if (result == NULL || result->nodes == NULL) {
		return NULL;
	}

	node = result->nodes;
	copy = (struct addrinfo *)calloc(1, sizeof(*copy));
	if (copy == NULL) {
		return NULL;
	}

	copy->ai_family = node->ai_family;
	copy->ai_socktype = node->ai_socktype;
	copy->ai_protocol = node->ai_protocol;
	copy->ai_addrlen = node->ai_addrlen;
	copy->ai_flags = node->ai_flags;

	if (node->ai_addr != NULL && node->ai_addrlen > 0) {
		copy->ai_addr = (struct sockaddr *)malloc(node->ai_addrlen);
		if (copy->ai_addr == NULL) {
			free(copy);
			return NULL;
		}
		memcpy(copy->ai_addr, node->ai_addr, node->ai_addrlen);
	}

	return copy;
}

static void spine_async_dns_complete(async_dns_query_ctx_t *ctx, struct addrinfo *res, int status) {
	if (ctx == NULL || ctx->completed) {
		spine_async_dns_free_addrinfo(res);
		return;
	}

	ctx->completed = true;
	ctx->callback(res, status, ctx->data);
	spine_async_dns_free_addrinfo(res);
	free(ctx);
}

static async_dns_watcher_t *spine_async_dns_find_watcher(spine_async_dns_runtime_t *runtime, ares_socket_t fd) {
	async_dns_watcher_t *watcher = runtime->watchers;

	while (watcher != NULL) {
		if (watcher->fd == fd) {
			return watcher;
		}
		watcher = watcher->next;
	}

	return NULL;
}

static void spine_async_dns_timer_refresh(spine_async_dns_runtime_t *runtime);

static void spine_async_dns_on_poll_closed(uv_handle_t *handle) {
	async_dns_watcher_t *watcher = (async_dns_watcher_t *)handle->data;
	spine_async_dns_runtime_t *runtime = watcher != NULL ? watcher->runtime : NULL;

	if (runtime != NULL && runtime->close_refs > 0) {
		runtime->close_refs--;
	}
	if (runtime != NULL && runtime->close_refs == 0 && !runtime->initialized) {
		free(runtime);
	}

	free(watcher);
}

static void spine_async_dns_on_timer_closed(uv_handle_t *handle) {
	spine_async_dns_runtime_t *runtime = (spine_async_dns_runtime_t *)handle->data;
	if (runtime == NULL) {
		return;
	}

	if (runtime->close_refs > 0) {
		runtime->close_refs--;
	}
	if (runtime->close_refs == 0 && !runtime->initialized) {
		free(runtime);
	}
}

static void spine_async_dns_close_watcher(async_dns_watcher_t *watcher) {
	if (watcher == NULL || watcher->closing) {
		return;
	}

	watcher->closing = true;
	uv_poll_stop(&watcher->poll);
	uv_close((uv_handle_t *)&watcher->poll, spine_async_dns_on_poll_closed);
}

static void spine_async_dns_remove_watcher(spine_async_dns_runtime_t *runtime, ares_socket_t fd) {
	async_dns_watcher_t **cursor = &runtime->watchers;

	while (*cursor != NULL) {
		async_dns_watcher_t *watcher = *cursor;
		if (watcher->fd == fd) {
			*cursor = watcher->next;
			watcher->next = NULL;
			spine_async_dns_close_watcher(watcher);
			return;
		}
		cursor = &watcher->next;
	}
}

static void spine_async_dns_on_poll(uv_poll_t *handle, int status, int events) {
	async_dns_watcher_t *watcher = (async_dns_watcher_t *)handle->data;
	spine_async_dns_runtime_t *runtime;
	ares_socket_t read_fd = ARES_SOCKET_BAD;
	ares_socket_t write_fd = ARES_SOCKET_BAD;
	ares_socket_t captured_fd;

	if (watcher == NULL) {
		return;
	}

	runtime = watcher->runtime;
	if (runtime == NULL || runtime->channel == NULL || runtime->shutting_down) {
		return;
	}

	/* Capture the fd before calling ares_process_fd. The watcher struct
	 * itself may be invalidated by a sock_state_cb reentry during
	 * ares_process_fd (c-ares calls back into
	 * spine_async_dns_upsert_watcher -> spine_async_dns_remove_watcher,
	 * which frees this watcher); never touch `watcher` after the call. */
	captured_fd = watcher->fd;
	(void)captured_fd;  /* currently only used via read_fd/write_fd above */

	if (status < 0) {
		read_fd = watcher->fd;
		write_fd = watcher->fd;
	} else {
		if ((events & UV_READABLE) != 0) {
			read_fd = watcher->fd;
		}
		if ((events & UV_WRITABLE) != 0) {
			write_fd = watcher->fd;
		}
	}

	ares_process_fd(runtime->channel, read_fd, write_fd);
	/* watcher may be freed here; only runtime is safe to use. */
	spine_async_dns_timer_refresh(runtime);
}

static void spine_async_dns_upsert_watcher(spine_async_dns_runtime_t *runtime, ares_socket_t fd, int readable, int writable) {
	async_dns_watcher_t *watcher;
	int uv_events = 0;

	if (runtime == NULL || runtime->shutting_down || runtime->loop == NULL) {
		return;
	}

	if (!readable && !writable) {
		spine_async_dns_remove_watcher(runtime, fd);
		spine_async_dns_timer_refresh(runtime);
		return;
	}

	if (readable) {
		uv_events |= UV_READABLE;
	}
	if (writable) {
		uv_events |= UV_WRITABLE;
	}

	watcher = spine_async_dns_find_watcher(runtime, fd);
	if (watcher == NULL) {
		watcher = (async_dns_watcher_t *)calloc(1, sizeof(*watcher));
		if (watcher == NULL) {
			return;
		}

		watcher->runtime = runtime;
		watcher->fd = fd;
		watcher->poll.data = watcher;
		if (uv_poll_init_socket(runtime->loop, &watcher->poll, (uv_os_sock_t)fd) != 0) {
			free(watcher);
			return;
		}

		watcher->next = runtime->watchers;
		runtime->watchers = watcher;
	}

	if (uv_poll_start(&watcher->poll, uv_events, spine_async_dns_on_poll) != 0) {
		spine_async_dns_remove_watcher(runtime, fd);
		return;
	}

	spine_async_dns_timer_refresh(runtime);
}

static void spine_async_dns_socket_state_cb(void *data, ares_socket_t fd, int readable, int writable) {
	spine_async_dns_runtime_t *runtime = (spine_async_dns_runtime_t *)data;
	spine_async_dns_upsert_watcher(runtime, fd, readable, writable);
}

static void spine_async_dns_on_timer(uv_timer_t *handle) {
	spine_async_dns_runtime_t *runtime = (spine_async_dns_runtime_t *)handle->data;

	if (runtime == NULL || runtime->channel == NULL || runtime->shutting_down) {
		return;
	}

	ares_process_fd(runtime->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
	spine_async_dns_timer_refresh(runtime);
}

static void spine_async_dns_timer_refresh(spine_async_dns_runtime_t *runtime) {
	struct timeval tv;
	struct timeval *next_timeout;
	uint64_t timeout_ms;

	if (runtime == NULL || !runtime->timer_initialized || runtime->channel == NULL || runtime->shutting_down) {
		return;
	}

	next_timeout = ares_timeout(runtime->channel, NULL, &tv);
	if (next_timeout == NULL) {
		if (runtime->timer_started) {
			uv_timer_stop(&runtime->timer);
			runtime->timer_started = false;
		}
		return;
	}

	timeout_ms = ((uint64_t)next_timeout->tv_sec * 1000U) + ((uint64_t)next_timeout->tv_usec / 1000U);
	if (timeout_ms == 0) {
		timeout_ms = 1;
	}

	if (uv_timer_start(&runtime->timer, spine_async_dns_on_timer, timeout_ms, 0) == 0) {
		runtime->timer_started = true;
	}
}

static void spine_async_dns_on_resolved(void *arg, int status, int timeouts, struct ares_addrinfo *result) {
	async_dns_query_ctx_t *ctx = (async_dns_query_ctx_t *)arg;
	struct addrinfo *first = NULL;
	(void)timeouts;

	if (status == ARES_SUCCESS && result != NULL) {
		first = spine_async_dns_clone_first_addrinfo(result);
	}

	if (result != NULL) {
		ares_freeaddrinfo(result);
	}

	spine_async_dns_complete(ctx, first, status);
}

int spine_async_dns_runtime_create(uv_loop_t *dns_loop, spine_async_dns_runtime_t **out_runtime) {
	struct ares_options opts;
	spine_async_dns_runtime_t *runtime;
	int optmask = 0;
	int status;

	if (dns_loop == NULL || out_runtime == NULL) {
		return -EINVAL;
	}

	*out_runtime = NULL;

	runtime = (spine_async_dns_runtime_t *)calloc(1, sizeof(*runtime));
	if (runtime == NULL) {
		return -ENOMEM;
	}
	runtime->loop = dns_loop;

	status = ares_library_init(ARES_LIB_INIT_ALL);
	if (status != ARES_SUCCESS) {
		free(runtime);
		return -status;
	}

	memset(&opts, 0, sizeof(opts));
	opts.sock_state_cb = spine_async_dns_socket_state_cb;
	opts.sock_state_cb_data = runtime;
	optmask |= ARES_OPT_SOCK_STATE_CB;

	status = ares_init_options(&runtime->channel, &opts, optmask);
	if (status != ARES_SUCCESS) {
		ares_library_cleanup();
		free(runtime);
		return -status;
	}

	if (uv_timer_init(runtime->loop, &runtime->timer) != 0) {
		ares_destroy(runtime->channel);
		runtime->channel = NULL;
		ares_library_cleanup();
		free(runtime);
		return -1;
	}
	runtime->timer.data = runtime;

	runtime->timer_initialized = true;
	runtime->timer_started = false;
	runtime->initialized = true;
	runtime->close_refs = 0;
	*out_runtime = runtime;
	return 0;
}

void spine_async_dns_runtime_destroy(spine_async_dns_runtime_t *runtime) {
	async_dns_watcher_t *watcher;

	if (runtime == NULL || !runtime->initialized) {
		return;
	}

	runtime->shutting_down = true;

	if (runtime->timer_started) {
		uv_timer_stop(&runtime->timer);
		runtime->timer_started = false;
	}
	if (runtime->timer_initialized && !uv_is_closing((uv_handle_t *)&runtime->timer)) {
		runtime->close_refs++;
		uv_close((uv_handle_t *)&runtime->timer, spine_async_dns_on_timer_closed);
	}

	if (runtime->channel != NULL) {
		ares_destroy(runtime->channel);
		runtime->channel = NULL;
	}

	while (runtime->watchers != NULL) {
		watcher = runtime->watchers;
		runtime->watchers = watcher->next;
		watcher->next = NULL;
		runtime->close_refs++;
		spine_async_dns_close_watcher(watcher);
	}

	runtime->timer_initialized = false;
	runtime->initialized = false;
	runtime->loop = NULL;
	ares_library_cleanup();
	if (runtime->close_refs == 0) {
		free(runtime);
	}
}

int spine_async_dns_lookup_runtime(spine_async_dns_runtime_t *runtime, const char *hostname, async_dns_cb cb, void *data) {
	async_dns_query_ctx_t *ctx;
	struct ares_addrinfo_hints hints;

	if (runtime == NULL || !runtime->initialized || hostname == NULL || cb == NULL) {
		return -EINVAL;
	}

	ctx = (async_dns_query_ctx_t *)calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return -ENOMEM;
	}

	ctx->runtime = runtime;
	ctx->callback = cb;
	ctx->data = data;
	ctx->completed = false;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	ares_getaddrinfo(runtime->channel, hostname, NULL, &hints, spine_async_dns_on_resolved, ctx);
	spine_async_dns_timer_refresh(runtime);
	return 0;
}

#else

struct spine_async_dns_runtime {
	uv_loop_t *loop;
	bool initialized;
	/* uv_getaddrinfo submits a request, not a handle; uv_walk will not
	 * see it, so uv_loop_close returns EBUSY if a lookup is in flight
	 * on shutdown. Track the count here so the shutdown path can spin
	 * a bounded wait-for-drain before closing the loop. */
	int inflight;
};

typedef struct {
	uv_getaddrinfo_t req;
	async_dns_cb callback;
	void *data;
	spine_async_dns_runtime_t *runtime;
} async_dns_ctx_t;

static void on_resolved(uv_getaddrinfo_t *req, int status, struct addrinfo *res) {
	async_dns_ctx_t *ctx = (async_dns_ctx_t *)req->data;

	if (status == 0) {
		ctx->callback(res, 0, ctx->data);
		uv_freeaddrinfo(res);
	} else {
		ctx->callback(NULL, status, ctx->data);
	}

	if (ctx->runtime != NULL && ctx->runtime->inflight > 0) {
		ctx->runtime->inflight--;
	}
	free(ctx);
}

int spine_async_dns_inflight(spine_async_dns_runtime_t *runtime) {
	return runtime != NULL ? runtime->inflight : 0;
}

int spine_async_dns_runtime_create(uv_loop_t *dns_loop, spine_async_dns_runtime_t **out_runtime) {
	spine_async_dns_runtime_t *runtime;

	if (dns_loop == NULL || out_runtime == NULL) {
		return -EINVAL;
	}

	runtime = (spine_async_dns_runtime_t *)calloc(1, sizeof(*runtime));
	if (runtime == NULL) {
		return -ENOMEM;
	}

	runtime->loop = dns_loop;
	runtime->initialized = true;
	*out_runtime = runtime;
	return 0;
}

void spine_async_dns_runtime_destroy(spine_async_dns_runtime_t *runtime) {
	if (runtime == NULL) {
		return;
	}

	/* Bounded wait for outstanding uv_getaddrinfo requests before free.
	 * uv_loop_close returns EBUSY if a request is still in flight and
	 * hangs the shutdown path. Give each inflight request up to ~3s to
	 * complete; that matches typical getaddrinfo(3) timeouts. */
	int deadline_ticks = 300; /* 300 x 10ms == 3s */
	while (runtime->inflight > 0 && deadline_ticks > 0 && runtime->loop != NULL) {
		uv_run(runtime->loop, UV_RUN_NOWAIT);
		deadline_ticks--;
	}

	free(runtime);
}

int spine_async_dns_lookup_runtime(spine_async_dns_runtime_t *runtime, const char *hostname, async_dns_cb cb, void *data) {
	async_dns_ctx_t *ctx;
	struct addrinfo hints;
	int rc;

	if (runtime == NULL || !runtime->initialized || hostname == NULL || cb == NULL) {
		return -EINVAL;
	}

	ctx = (async_dns_ctx_t *)calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return -ENOMEM;
	}

	ctx->callback = cb;
	ctx->data = data;
	ctx->req.data = ctx;
	ctx->runtime = runtime;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	rc = uv_getaddrinfo(runtime->loop, &ctx->req, on_resolved, hostname, NULL, &hints);
	if (rc != 0) {
		free(ctx);
	} else {
		runtime->inflight++;
	}
	return rc;
}
#endif
