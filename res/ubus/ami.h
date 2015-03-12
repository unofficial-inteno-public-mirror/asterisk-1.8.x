/*
 * ami.h
 *
 *  Created on: Oct 13, 2014
 *      Author: kj
 */

#ifndef AMI_H_
#define AMI_H_

struct ami;

struct brcm_event {
	enum {
		BRCM_UNKNOWN_EVENT,
		BRCM_STATUS_EVENT,
		BRCM_STATE_EVENT,
		BRCM_MODULE_EVENT
	} type;
	struct {
		int line_id;
		int off_hook;
	} status;
	struct {
		int line_id;
		int subchannel_id;
		char* state;
	} state;
	int module_loaded;
};

struct registry_event {
	char* account_name;
	enum {
		REGISTRY_UNKNOWN_EVENT,
		REGISTRY_REQUEST_SENT_EVENT,
		REGISTRY_UNREGISTERED_EVENT,
		REGISTRY_REGISTERED_EVENT
	} status;
};

struct registry_entry_event {
	char* host;				//Account name (e.g. sip0)
	int port;				//5060
	char* username;			//0510409896
	char* domain;			//62.80.209.10
	int domain_port;		//5060
	int refresh;			//Refresh interval, 285
	char* state;			//Registration state Registered
	int registration_time;	//Registration timestamp, 1401282865
};

struct channel_reload_event {
	enum {
		CHANNELRELOAD_UNKNOWN_EVENT,
		CHANNELRELOAD_SIP_EVENT
	} channel_type;
};

struct varset_event {
	char* channel;
	char* variable;
	char* value;
};

enum ami_event_type {
	LOGIN,
	REGISTRY,
	REGISTRY_ENTRY,
	REGISTRATIONS_COMPLETE,
	BRCM,
	CHANNELRELOAD,
	FULLYBOOTED,
	VARSET,
	DISCONNECT,
	UNKNOWN_EVENT,
};

struct ami_event {
	enum ami_event_type type;
	struct brcm_event *brcm_event;
	struct registry_event *registry_event;
	struct registry_entry_event *registry_entry_event;
	struct channel_reload_event *channel_reload_event;
	struct varset_event *varset_event;
};

struct ami_response {
	char *response;
	void *userdata;
};

enum ami_message_type {
	UNKNOWN_MESSAGE,
	LOGIN_MESSAGE,
	EVENT_MESSAGE,
	RESPONSE_MESSAGE
};

struct ami_message {
	enum ami_message_type type;
	struct ami_event *event;
	struct ami_response *response;
	struct ami_message *next;
};


/* Setup a new ami */
struct ami *ami_setup(int fd);

/* Disconnect ami and free memory */
void ami_free(struct ami *mgr);

/* Lock ami */
int ami_lock(struct ami *mgr);

/* Unlock ami */
int ami_unlock(struct ami *mgr);

/* Get next message (if any), caller must free result */
struct ami_message *ami_get_next_message(struct ami *mgr);

/* Delete an ami message (event or response) */
void ami_message_free(struct ami_message *data);

/* Queue action 'sip show registry' */
void ami_action_send_sip_show_registry(struct ami *mgr);

/* Queue action 'sip reload' */
void ami_action_send_sip_reload(struct ami *mgr);

void ami_action_send_brcm_dump(struct ami *mgr, void *userdata);

void ami_action_send_sip_dump(struct ami *mgr, void *userdata);

/*
 * Request an indication on if BRCM module is loaded or not
 *
 * Example response:
 * "Response: Follows
 * Privilege: Command
 * --END COMMAND--"
 */
void ami_send_module_show_brcm(struct ami *mgr, void *userdata);

/*
 * Request an indication on the port configuration
 *
 * Example response:
 * "Response: Success
 * Message:
 * FXS 2
 * DECT 4"
 */
void ami_send_brcm_ports_show(struct ami *mgr, void *userdata);

#endif /* AMI_H_ */
