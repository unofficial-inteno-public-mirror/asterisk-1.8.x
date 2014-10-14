/*
 * manager_listener.h
 *
 *  Created on: Oct 13, 2014
 *      Author: kj
 */

#ifndef MANAGER_LISTENER_H_
#define MANAGER_LISTENER_H_

struct manager_listener_data;
struct manager_listener;

/* Setup a new manager listener */
struct manager_listener *manager_listener_setup(int fd);

/* Disconnect manager listener and free memory */
void manager_listener_free(struct manager_listener *mgr);

/* Get event file descriptor for use with select */
int manager_listener_fd(struct manager_listener *mgr);

/* Lock manager listener */
int manager_listener_lock(struct manager_listener *mgr);

/* Unlock manager listener */
int manager_listener_unlock(struct manager_listener *mgr);

/* Get next data item (if any), caller must free result */
struct manager_listener_data *manager_listener_get_next_data(struct manager_listener *mgr);

/* Get manager data category */
int manager_listener_data_get_category(struct manager_listener_data *data);

/* Get manager data event */
const char *manager_listener_data_get_event(struct manager_listener_data *data);

/* Get manager data content */
const char *manager_listener_data_get_content(struct manager_listener_data *data);

/* Delete a manager data item*/
void manager_listener_data_free(struct manager_listener_data *data);

#endif /* MANAGER_LISTENER_H_ */
