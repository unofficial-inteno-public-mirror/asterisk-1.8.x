/*
 * manager_listener.c
 *
 *  Created on: Oct 13, 2014
 *      Author: kj
 */

#include "manager_listener.h"

#define BUF_SIZE 32
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/eventfd.h>

#include "asterisk.h"
#include "asterisk/strings.h"
#include "asterisk/manager.h"
#include "asterisk/logger.h"

struct manager_listener_data {
	int category;
	char* event;
	char* content;
	struct manager_listener_data *next;
};

struct manager_listener {
	int fd;									//Pipe fd, a byte is written to this pipe when data is available
	ast_mutex_t lock;						//When locked, owner has listener struct, queue and all queue items
	struct manager_custom_hook hook;		//Manager hook data
	struct manager_listener_data *queue;	//Events or command response read from manager
};

// Called for each manager event and command response
static int manager_hook_cb(int catergory, const char* event, char* content, void *data);

struct manager_listener *manager_listener_setup(int fd)
{
	// Setup manager listener
	struct manager_listener *mgr = malloc(sizeof(struct manager_listener));
	mgr->fd = fd;
	ast_mutex_init(&mgr->lock);
	mgr->queue = NULL;

	// Callback
	mgr->hook.file = malloc(sizeof(char) * BUF_SIZE);
	snprintf(mgr->hook.file, sizeof(char) * BUF_SIZE, "manager_listener_%d", fd);
	mgr->hook.helper = manager_hook_cb;
	mgr->hook.data = mgr;
	ast_manager_register_hook(&mgr->hook);

	return mgr;
}

void manager_listener_free(struct manager_listener *mgr)
{
	ast_manager_unregister_hook(&mgr->hook);

	free(mgr->hook.file);

	// Free any unread data
	while (mgr->queue) {
		struct manager_listener_data *next = mgr->queue->next;
		manager_listener_data_free(mgr->queue);
		mgr->queue = next;
	}

	free(mgr);
}

int manager_listener_lock(struct manager_listener *mgr)
{
	return ast_mutex_lock(&mgr->lock);
}

int manager_listener_unlock(struct manager_listener *mgr)
{
	return ast_mutex_unlock(&mgr->lock);
}

struct manager_listener_data *manager_listener_get_next_data(struct manager_listener *mgr)
{
	struct manager_listener_data *data;
	manager_listener_lock(mgr);

	if (mgr->queue) {
		// Unlink and return first data item
		data = mgr->queue;
		mgr->queue = data->next;
	}
	else {
		// Empty queue
		data = NULL;
	}
	manager_listener_unlock(mgr);

	return data;
}

static int manager_hook_cb(int catergory, const char* event, char* content, void *caller_data)
{
	struct manager_listener *mgr = (struct manager_listener *) caller_data;
	char c = '\0';

	// Create data item
	struct manager_listener_data *manager_data = malloc(sizeof(struct manager_listener_data));
	manager_data->category = catergory;
	manager_data->event = strdup(event);
	manager_data->content = strdup(content);
	manager_data->next = NULL;

	// Push data item on manager listener queue
	manager_listener_lock(mgr);

	struct manager_listener_data *queue_tmp = mgr->queue;
	while (queue_tmp) {
		queue_tmp = queue_tmp->next;
	}
	if (queue_tmp) {
		queue_tmp->next = manager_data;
	}
	else {
		mgr->queue = manager_data;
	}

	// Notify client that new data is available
	if (write(mgr->fd, &c, sizeof(char)) < 0) {
		ast_log(LOG_ERROR, "manager_listener: failed to notify listener: %s\n", strerror(errno));
	}

	manager_listener_unlock(mgr);
	return 0;
}

int manager_listener_data_get_category(struct manager_listener_data *data)
{
	return data->category;
}

const char *manager_listener_data_get_event(struct manager_listener_data *data)
{
	return data->event;
}

const char *manager_listener_data_get_content(struct manager_listener_data *data)
{
	return data->content;
}

void manager_listener_data_free(struct manager_listener_data *data)
{
	free(data->event);
	free(data->content);
	free(data);
}
