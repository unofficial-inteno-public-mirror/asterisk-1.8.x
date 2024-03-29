/*
 * ami.c
 *
 *  Created on: Oct 13, 2014
 *      Author: kj
 */

#include "ami.h"

#define BUF_SIZE 32
#define AMI_BUFLEN 512

#define MESSAGE_FRAME "\r\n\r\n"

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/eventfd.h>

#include "asterisk.h"
#include "asterisk/strings.h"
#include "asterisk/manager.h"
#include "asterisk/logger.h"

struct ami_action
{
	unsigned int id;
	char message[AMI_BUFLEN];
	void *userdata;
	struct ami_action* prev;
	struct ami_action* next;
};

struct ami
{
	int fd;                           //Pipe fd, a byte is written to this pipe when data is available
	ast_mutex_t lock;                 //When locked, owner has listener struct, queue and all queue items
	struct manager_custom_hook hook;  //Manager hook data
	struct ami_message *in_queue;     //Events or command response read from manager
	struct ami_action *pending_list;  //Pending actions which have been sent to manager
	char *read_buffer;                //Previously read incomplete data
	void (*refresh_cb)(void *userdata);//Action refresh callback
	unsigned int next_action_id;       //Next value to use for ActionID in an Action
};

static int manager_hook_cb(int catergory, const char* event, char* content, void *data);
static void send_action(struct ami *mgr, struct ami_action *action);
static struct ami_action *get_pending_action(struct ami *mgr, unsigned int id);


/********************/
/* Public functions */
/********************/
struct ami *ami_setup(int fd, void (*refresh_cb)(void *userdata))
{
	//Setup manager listener
	struct ami *mgr = malloc(sizeof(struct ami));
	mgr->fd = fd;
	mgr->refresh_cb = refresh_cb;
	mgr->next_action_id = 1;
	ast_mutex_init(&mgr->lock);
	mgr->in_queue = NULL;
	mgr->pending_list = NULL;
	mgr->read_buffer = NULL;

	//Callback
	mgr->hook.file = malloc(sizeof(char) * BUF_SIZE);
	snprintf(mgr->hook.file, sizeof(char) * BUF_SIZE, "ami_%d", fd);
	mgr->hook.helper = manager_hook_cb;
	mgr->hook.data = mgr;
	mgr->hook.list.next = NULL;
	ast_manager_register_hook(&mgr->hook);

	return mgr;
}

void ami_free(struct ami *mgr)
{
	ast_manager_unregister_hook(&mgr->hook);

	free(mgr->hook.file);

	//Free any unread data
	while (mgr->in_queue) {
		struct ami_message *next = mgr->in_queue->next;
		ami_message_free(mgr->in_queue);
		mgr->in_queue = next;
	}

	//Free any pending actions
	while (mgr->pending_list) {
		struct ami_action *next = mgr->pending_list->next;
		free(mgr->pending_list);
		mgr->pending_list = next;
	}

	if (mgr->read_buffer) {
		free(mgr->read_buffer);
	}

	free(mgr);
}

int ami_lock(struct ami *mgr)
{
	return ast_mutex_lock(&mgr->lock);
}

int ami_unlock(struct ami *mgr)
{
	return ast_mutex_unlock(&mgr->lock);
}

struct ami_message *ami_get_next_message(struct ami *mgr)
{
	struct ami_message *message = NULL;
	ami_lock(mgr);

	if (mgr->in_queue) {
		//Unlink and return first message
		message = mgr->in_queue;
		mgr->in_queue = message->next;
	}
	ami_unlock(mgr);

	return message;
}

void ami_message_free(struct ami_message *message)
{
	if (message->response) {
		struct ami_response *response = message->response;
		free(response->response);
		free(response);
	}

	if (message->event) {
		struct ami_event *event = message->event;
		switch (event->type) {
			case REGISTRY:
				free(event->registry_event->account_name);
				free(event->registry_event);
				break;
			case BRCM:
				if (event->brcm_event->type == BRCM_STATE_EVENT) {
					free(event->brcm_event->state.state);
				}
				free(event->brcm_event);
				break;
			case SIP:
				free(event->sip_event);
				break;
			case CHANNELRELOAD:
				free(event->channel_reload_event);
				break;
			case VARSET:
				free(event->varset_event->channel);
				free(event->varset_event->value);
				free(event->varset_event->variable);
				free(event->varset_event);
				break;
			case REGISTRY_ENTRY:
				free(event->registry_entry_event->host);
				free(event->registry_entry_event->domain);
				free(event->registry_entry_event->state);
				free(event->registry_entry_event->username);
				free(event->registry_entry_event);
				break;
			case FULLYBOOTED:
			case LOGIN:
			case DISCONNECT:
			case REGISTRATIONS_COMPLETE:
				/* no event data to free */
				break;
			case UNKNOWN_EVENT:
				break;
			default:
				ast_log(LOG_WARNING, "Unhandled event type, can't free (may leak)\n");
				break;
		}
		free(event);
	}

	free(message);
}

/*
 * Send command to reload sip channel.
 * CHANNELRELOAD event will be received when reload is completed.
 *
 * Example response:
 * "Response: Follows
 * Privilege: Command
 * --END COMMAND--"
 */
void ami_action_send_sip_reload(struct ami *mgr)
{
	ast_log(LOG_DEBUG, "Queueing Action: sip reload\n");
	struct ami_action* action = malloc(sizeof(struct ami_action));
	memset(action, 0, sizeof(struct ami_action));
	sprintf(action->message,"Action: Command\r\nCommand: sip reload\r\n");
	send_action(mgr, action);
}

/*
 * Request SIP Registry information
 * (response is a simple message, then the registry events
 * follow separately, one per registered account)
 * Example response:
 * Response: Success
 * EventList: start
 * Message: Registrations will follow
 *
 * Event: RegistryEntry
 * Host: sip0
 * Port: 5060
 * Username: 0510409896
 * Domain: 62.80.209.10
 * DomainPort: 5060
 * Refresh: 5385
 * State: Registered
 * RegistrationTime: 1401282865
 *
 * Event: RegistrationsComplete
 * EventList: Complete
 * ListItems: 1
 */
void ami_action_send_sip_show_registry(struct ami *mgr)
{
	ast_log(LOG_DEBUG, "Queueing Action: SIPshowregistry\n");
	struct ami_action* action = malloc(sizeof(struct ami_action));
	memset(action, 0, sizeof(struct ami_action));
	sprintf(action->message, "Action: SIPshowregistry\r\n");
	send_action(mgr, action);
}

void ami_send_module_show_sip(struct ami *mgr, void *userdata) {
	ast_log(LOG_DEBUG, "Queueing Action: module show like chan_sip\n");
	struct ami_action* action = malloc(sizeof(struct ami_action));
	memset(action, 0, sizeof(struct ami_action));
	sprintf(action->message, "Action: Command\r\nCommand: module show like chan_sip\r\n");
	action->userdata = userdata;
	send_action(mgr, action);
}

void ami_action_send_brcm_dump(struct ami *mgr, void *userdata)
{
	ast_log(LOG_DEBUG, "Queueing Action: BRCMdump\n");
	struct ami_action* action = malloc(sizeof(struct ami_action));
	memset(action, 0, sizeof(struct ami_action));
	sprintf(action->message, "Action: BRCMdump\r\n");
	action->userdata = userdata;
	send_action(mgr, action);
}

void ami_action_send_sip_dump(struct ami *mgr, void *userdata)
{
	ast_log(LOG_DEBUG, "Queueing Action: SIPdump\n");
	struct ami_action* action = malloc(sizeof(struct ami_action));
	memset(action, 0, sizeof(struct ami_action));
	sprintf(action->message, "Action: SIPdump\r\n");
	action->userdata = userdata;
	send_action(mgr, action);
}

void ami_send_module_show_brcm(struct ami *mgr, void *userdata) {
	ast_log(LOG_DEBUG, "Queueing Action: module show like chan_brcm\n");
	struct ami_action* action = malloc(sizeof(struct ami_action));
	memset(action, 0, sizeof(struct ami_action));
	sprintf(action->message, "Action: Command\r\nCommand: module show like chan_brcm\r\n");
	action->userdata = userdata;
	send_action(mgr, action);
}

void ami_send_brcm_ports_show(struct ami *mgr, void *userdata) {
	ast_log(LOG_DEBUG, "Queueing Action: BRCMPortsShow\n");
	struct ami_action* action = malloc(sizeof(struct ami_action));
	memset(action, 0, sizeof(struct ami_action));
	sprintf(action->message, "Action: BRCMPortsShow\r\n");
	action->userdata = userdata;
	send_action(mgr, action);
}

void ami_refresh(struct ami *mgr)
{
	struct ami_action* action;
	struct ami_action* next;

	ami_lock(mgr);

	if (mgr->refresh_cb) {
		action = mgr->pending_list;
		while (action) {
			next = action->next;
			mgr->refresh_cb(action->userdata);
			action = next;
		}
	}

	ami_unlock(mgr);
}

/**************************/
/* Private implementation */
/**************************/

/*
 * Send action or queue if another action is already pending
 */
static void send_action(struct ami *mgr, struct ami_action *action)
{
	char buf[32];

	action->id = mgr->next_action_id++;
	int field_len = snprintf(buf, sizeof(buf), "ActionID: %x\r\n", action->id);
	/*
	 * Make sure that we have enough space in the buffer to append the
	 * ActionID field.
	 */
	if (sizeof(action->message) - strlen(action->message) - sizeof("\r\n") < field_len) {
		ast_log(LOG_ERROR, "Cannot append ActionID to message\n");
		free(action);
		return;
	}
	else {
		/* Append the ActionID field and the sequence \r\n
		 * which marks the end of the message.
		 */
		strcat(action->message, buf);
		strcat(action->message, "\r\n");
	}

	ami_lock(mgr);

	/* Append to queue of pending actions */
	action->next = NULL;
	action->prev = NULL;
	if (mgr->pending_list) {
		struct ami_action* a = mgr->pending_list;
		while (a->next) {
			a = a->next;
		}
		a->next = action;
		action->prev = a;
	}
	else {
		mgr->pending_list = action;
	}

	if (ast_hook_send_action(&mgr->hook, action->message) < 0) {
		ast_log(LOG_ERROR, "Failed to send action\n");

		/* Remove action from pending list */
		get_pending_action(mgr, action->id);

		free(action);
	}

	ami_unlock(mgr);
}

/*
 * Lookup action by ID and remove it from list of pending actions.
 */
struct ami_action *get_pending_action(struct ami *mgr, unsigned int id)
{
	struct ami_action *pending_action;
	ami_lock(mgr);

	pending_action = mgr->pending_list;
	while (pending_action) {
		if (pending_action->id == id) {
			/* Remove action from list */
			if (!pending_action->prev && !pending_action->next) {
				/* List is now empty */
				mgr->pending_list = NULL;
			}
			else {
				/* Unlink action from the list */
				if (pending_action->next) {
					pending_action->next->prev = pending_action->prev;
				}
				if (pending_action->prev) {
					pending_action->prev->next = pending_action->next;
				}
			}
			ami_unlock(mgr);
			return pending_action;
		}

		pending_action = pending_action->next;
	}

	ami_unlock(mgr);
	return NULL;
}

/*
 * Find the type on an event and advance the idx buffer pointer
 * to the beginning of the event.
 */
static enum ami_event_type get_event_type(char* buf, int* idx)
{
	int i = 0;

	if (!memcmp(buf, "RegistryEntry", 13)) {
		i +=13;
		while((buf[i] == '\n') || (buf[i] == '\r'))
			i++;

		*idx = i;
		return REGISTRY_ENTRY;
	} else if (!memcmp(buf, "Registry", 8)) {
		i +=8;
		while((buf[i] == '\n') || (buf[i] == '\r'))
			i++;

		*idx = i;
		return REGISTRY;
	} else if (!memcmp(buf, "RegistrationsComplete", 4)) {
		i +=21;
		while((buf[i] == '\n') || (buf[i] == '\r'))
			i++;

		*idx = i;
		return REGISTRATIONS_COMPLETE;
	} else if (!memcmp(buf, "BRCM", 4)) {
		i +=8; /* SUSPICIOUS! */
		while((buf[i] == '\n') || (buf[i] == '\r'))
			i++;

		*idx = i;
		return BRCM;
	} else if (!memcmp(buf, "SIP", 3)) {
		i +=3;
		while((buf[i] == '\n') || (buf[i] == '\r'))
			i++;

		*idx = i;
		return SIP;
	} else if (!memcmp(buf, "ChannelReload", 13)) {
		i +=8;
		while((buf[i] == '\n') || (buf[i] == '\r'))
			i++;

		*idx = i;
		return CHANNELRELOAD;
	} else if (!memcmp(buf, "FullyBooted", 11)) {
		i +=11;
		while((buf[i] == '\n') || (buf[i] == '\r'))
			i++;

		*idx = i;
		return FULLYBOOTED;
	} else if (!memcmp(buf, "VarSet", 6)) {
		i +=6;
		while((buf[i] == '\n') || (buf[i] == '\r'))
			i++;

		*idx = i;
		return VARSET;
	} else {

	} // else if() handle other events

	while(buf[i] || i > AMI_BUFLEN) {
		if (buf[i] == '\n') {
			break;
		}
		i++;
	}
	*idx = i;
	return UNKNOWN_EVENT;
}

/*
 * Parse SIP registry events
 */
static void parse_registry_event(struct ami_event *event, char* buf)
{
	event->type = REGISTRY;
	event->registry_event = malloc(sizeof(struct registry_event));
	event->registry_event->status = REGISTRY_UNKNOWN_EVENT;
	event->registry_event->account_name = NULL;

	char* domain = strstr(buf, "Domain: ");
	if (domain) {
		domain += 8; //Increment pointer to start of domain name
		int len = 0;
		while (domain[len] && !isspace(domain[len])) {
			len++;
		}
		char* account_name = calloc(len + 1, sizeof(char));
		strncpy(account_name, domain, len);
		event->registry_event->account_name = account_name;
		ast_log(LOG_DEBUG, "Found domain: %s of length %d\n", account_name, len);
	}
	else {
		ast_log(LOG_WARNING, "No domain found in Registry event\n");
	}

	char* status = NULL;
	if ((status = strstr(buf, "Status: Request Sent"))) {
		event->registry_event->status = REGISTRY_REQUEST_SENT_EVENT;
	}
	else if ((status = strstr(buf, "Status: Unregistered"))) {
		event->registry_event->status = REGISTRY_UNREGISTERED_EVENT;
	}
	else if ((status = strstr(buf, "Status: Registered"))) {
		event->registry_event->status = REGISTRY_REGISTERED_EVENT;
	}
	else {
		ast_log(LOG_WARNING, "No status found in Registry event\n");
	}
}

/*
 * Parse SIP registry entry events
 */
static void parse_registry_entry_event(struct ami_event *event, char* buf)
{
	event->type = REGISTRY_ENTRY;
	event->registry_entry_event = malloc(sizeof(struct registry_entry_event));
	event->registry_entry_event->host = 0;
	event->registry_entry_event->port = 0;
	event->registry_entry_event->username = 0;
	event->registry_entry_event->domain = 0;
	event->registry_entry_event->refresh = 0;
	event->registry_entry_event->state = 0;
	event->registry_entry_event->registration_time = 0;

	char* host_start = strstr(buf, "Host:");
	if (host_start) {
		//Found host
		host_start += 6; //Advance to start of content
		char* host_end = strstr(host_start, "\r\n");
		if (host_end) {
			//Found end of host
			int host_len = host_end - host_start;
			event->registry_entry_event->host = (char*)calloc(host_len + 1, 1);
			strncpy(event->registry_entry_event->host, host_start, host_len);
		}
	}

	char* port_start = strstr(buf, "Port:");
	if (port_start) {
		//Found port
		port_start += 6; //Advance to start of content
		event->registry_entry_event->port = strtol(port_start, NULL, 10);
	}

	char* username_start = strstr(buf, "Username:");
	if (username_start) {
		//Found username
		username_start += 10; //Advance to start of content
		char* username_end = strstr(username_start, "\r\n");
		if (username_end) {
			//Found end of username
			int username_len = username_end - username_start;
			event->registry_entry_event->username = (char*)calloc(username_len + 1, 1);
			strncpy(event->registry_entry_event->username, username_start, username_len);
		}
	}

	char* domain_start = strstr(buf, "Domain:");
	if (domain_start) {
		//Found domain
		domain_start += 8; //Advance to start of content
		char* domain_end = strstr(domain_start, "\r\n");
		if (domain_end) {
			//Found end of domain
			int domain_len = domain_end - domain_start;
			event->registry_entry_event->domain = (char*)calloc(domain_len + 1, 1);
			strncpy(event->registry_entry_event->domain, domain_start, domain_len);
		}
	}

	char* domain_port_start = strstr(buf, "DomainPort:");
	if (domain_port_start) {
		//Found port
		domain_port_start += 12; //Advance to start of content
		event->registry_entry_event->port = strtol(domain_port_start, NULL, 10);
	}

	char* refresh_start = strstr(buf, "Refresh:");
	if (refresh_start) {
		//Found refresh interval
		refresh_start += 9; //Advance to start of content
		event->registry_entry_event->refresh = strtol(refresh_start, NULL, 10);
	}

	char* state_start = strstr(buf, "State:");
	if (state_start) {
		//Found state
		state_start += 7; //Advance to start of content
		char* state_end = strstr(state_start, "\r\n");
		if (state_end) {
			//Found end of state
			int state_len = state_end - state_start;
			event->registry_entry_event->state = (char*)calloc(state_len + 1, 1);
			strncpy(event->registry_entry_event->state, state_start, state_len);
		}
	}

	char* registration_time_start = strstr(buf, "RegistrationTime:");
	if (registration_time_start) {
		//Found reg timestamp
		registration_time_start += 18; //Advance to start of content
		event->registry_entry_event->registration_time = strtol(registration_time_start, NULL, 10);
	}
}

/*
 * Parse BRCM events
 */
static struct ami_event *parse_brcm_event(struct ami_event *event, char* buf)
{
	event->type = BRCM;
	event->brcm_event = malloc(sizeof(struct brcm_event));
	event->brcm_event->type = BRCM_UNKNOWN_EVENT;

	char* event_type = NULL;

	if ((event_type = strstr(buf, "Status: "))) {
		event->brcm_event->type = BRCM_STATUS_EVENT;
		char status[255] = {0}; 
		int line_id = -1; 
		int num = sscanf(event_type + 8, "%s %d", status, &line_id); 
		if(num > 0){
			if(strcmp(status, "ON") == 0){
				event->brcm_event->status.off_hook = 0; 
			} else if(strcmp(status, "OFF") == 0){
				event->brcm_event->status.off_hook = 1; 
			} else {
				ast_log(LOG_WARNING, "Unknown status in brcm status event\n");
			}
		} else {
			ast_log(LOG_WARNING, "No status in brcm status event\n");
		}
		event->brcm_event->status.line_id = line_id; 
		if(line_id == -1){
			ast_log(LOG_WARNING, "No/Unknown line id in brcm status event\n");
		}
	}
	else if ((event_type = strstr(buf, "State: "))) {
		event->brcm_event->type = BRCM_STATE_EVENT;
		char state[255] = {0}; 
		int line_id = -1, subchannel = -1;
		int num = sscanf(event_type + 7, "%s %d %d", state, &line_id, &subchannel); 
		if(num > 0){
			event->brcm_event->state.state = calloc(strlen(state) + 1, sizeof(char)); 
			strcpy(event->brcm_event->state.state, state); 
		} else {
			event->brcm_event->state.state = NULL; 
		}
		event->brcm_event->state.line_id = line_id; 
		event->brcm_event->state.subchannel_id = subchannel;
	}
	else if ((event_type = strstr(buf, "Module unload"))) {
		event->brcm_event->type = BRCM_MODULE_EVENT;
		event->brcm_event->module_loaded = 0;
	}
	else if ((event_type = strstr(buf, "Module load"))) {
		event->brcm_event->type = BRCM_MODULE_EVENT;
		event->brcm_event->module_loaded = 1;
	}

	return event;
}

/*
 * Parse SIP events
 */
static struct ami_event *parse_sip_event(struct ami_event *event, char* buf)
{
	event->type = SIP;
	event->sip_event = malloc(sizeof(struct sip_event));
	event->sip_event->type = SIP_UNKNOWN_EVENT;

	char* event_type = NULL;

	if ((event_type = strstr(buf, "Module unload"))) {
		event->sip_event->type = SIP_MODULE_EVENT;
		event->sip_event->module_loaded = 0;
	}
	else if ((event_type = strstr(buf, "Module load"))) {
		event->sip_event->type = SIP_MODULE_EVENT;
		event->sip_event->module_loaded = 1;
	}

	return event;
}

/*
 * Parse varset events
 */
static void parse_varset_event(struct ami_event *event, char* buf)
{
	int len;
	event->type = VARSET;
	event->varset_event = malloc(sizeof(struct varset_event));

	char* channel = strstr(buf, "Channel: ");
	if (channel) {
		channel += 9; //Increment pointer to start of channel
		len = 0;
		while (channel[len] && !isspace(channel[len])) {
			len++;
		}
		event->varset_event->channel = calloc(len + 1, sizeof(char));
		strncpy(event->varset_event->channel, channel, len);
	}
	else {
		ast_log(LOG_WARNING, "No Channel in varset event\n");
		event->varset_event->channel = NULL;
	}

	char* variable = strstr(buf, "Variable: ");
	if (variable) {
		variable += 10; //Increment pointer to start of variable
		len = 0;
		while (variable[len] && !isspace(variable[len])) {
			len++;
		}
		event->varset_event->variable = calloc(len + 1, sizeof(char));
		strncpy(event->varset_event->variable, variable, len);
	}
	else {
		ast_log(LOG_WARNING, "No Variable in varset event\n");
		event->varset_event->variable = NULL;
	}

	char* value = strstr(buf, "Value: ");
	if (value) {
		value += 7; //Increment pointer to start of value
		len = 0;
		while (value[len] && !isspace(value[len])) {
			len++;
		}
		event->varset_event->value = calloc(len + 1, sizeof(char));
		strncpy(event->varset_event->value, value, len);
	}
	else {
		ast_log(LOG_WARNING, "No Value in varset event\n");
		event->varset_event->value = NULL;
	}
}

/*
 * Parse channel reload events
 */
static void parse_channel_reload_event(struct ami_event *event, char* buf) {
	event->type = CHANNELRELOAD;
	event->channel_reload_event = malloc(sizeof(struct channel_reload_event));

	char* result;
	if ((result = strstr(buf, "ChannelType: SIP"))) {
		event->channel_reload_event->channel_type = CHANNELRELOAD_SIP_EVENT;
	}
	else {
		ast_log(LOG_WARNING, "unknown channel in ChannelReload event\n");
		event->channel_reload_event->channel_type = CHANNELRELOAD_UNKNOWN_EVENT;
	}
}

/*
 * Parse fully booted events
 */
static void parse_fully_booted_event(struct ami_event *event, char* buf)
{
	event->type = FULLYBOOTED;
}

/*
 * Parse messages of type RESPONSE. As of now, raw message is just
 * copied into response struct
 */
static struct ami_response* parse_response(char* message)
{
	struct ami_response *response;
	char *tmp;

	response = calloc(1, sizeof(struct ami_response));
	if (!response) {
		ast_log(LOG_ERROR, "Failed to allocate memory\n");
		return NULL;
	}

	response->response = strdup(message);

	/* Extract ActionID field */
	tmp = strstr(response->response, "ActionID:");
	if (tmp) {
		sscanf(tmp, "ActionID: %x\r\n", &response->id);
	}

	return response;
}

/*
 * Parse messages of type EVENT
 */
static struct ami_event* parse_event(char* message)
{
	int idx = 0;
	enum ami_event_type type = get_event_type(message, &idx);
	struct ami_event *event;

	event = calloc(1, sizeof(struct ami_event));

	switch(type) {
		case BRCM:
			parse_brcm_event(event, &message[idx]);
			break;
		case SIP:
			parse_sip_event(event, &message[idx]);
			break;
		case CHANNELRELOAD:
			parse_channel_reload_event(event, &message[idx]);
			break;
		case FULLYBOOTED:
			parse_fully_booted_event(event, &message[idx]);
			break;
		case VARSET:
			parse_varset_event(event, &message[idx]);
			break;
		case REGISTRY:
			parse_registry_event(event, &message[idx]);
			break;
		case REGISTRY_ENTRY:
			parse_registry_entry_event(event, &message[idx]);
			break;
		case REGISTRATIONS_COMPLETE:
			/*
			 * Probably not needed.
			 * (this happens after all registry entry events have been received)
			 * Event: RegistrationsComplete
			 * EventList: Complete
			 * ListItems: 1
			*/
			event->type = REGISTRATIONS_COMPLETE;
			break;
		case UNKNOWN_EVENT:
		default:
			event->type = UNKNOWN_EVENT;
			break;
	}

	return event;
}

/*
 * Parse message type from raw data
 */
static enum ami_message_type parse_message_type(char *buffer)
{
	if (strlen(buffer) == 0) {
		ast_log(LOG_ERROR, "Empty buffer\n");
		return UNKNOWN_MESSAGE;
	}

	//Find out what type of message this is
	enum ami_message_type message_type;

	if (!strncmp(buffer, "Event", 5)) {
		message_type = EVENT_MESSAGE;
	}
	else if(!strncmp(buffer, "Response", 8)) {
		message_type = RESPONSE_MESSAGE;
	}
	else {
		message_type = UNKNOWN_MESSAGE;
	}

	return message_type;
}

/*
 * Parse raw message data from AMI. Returns parsed struct ami_message which
 * is of type RESPONSE_MESSAGE or EVENT_MESSAGE. All other message types
 * are discarded.
 */
static struct ami_message *parse_data(struct ami *mgr, const char *in_buf)
{
	char *buf;

	if (mgr->read_buffer) {

		//Previously read data exists, allocate space for old and new data
		buf = malloc(sizeof(char) * (strlen(in_buf) + strlen(mgr->read_buffer) + 1));
		if (!buf) {
			ast_log(LOG_ERROR, "Memory allocation failed\n");
			return NULL;
		}

		//Concatenate old and new data
		strcpy(buf, mgr->read_buffer);
		strcat(buf, in_buf);

		//Clear old read buffer, it's reset below if still unable to frame a message
		free(mgr->read_buffer);
		mgr->read_buffer = NULL;
	}
	else {

		//No previously unframed data
		buf = strdup(in_buf);
		if (!buf) {
			ast_log(LOG_ERROR, "Memory allocation failed\n");
			return NULL;
		}
	}

	//Locate message frame
	char *message_end = strstr(buf, MESSAGE_FRAME);
	if (!message_end) {
		//Incomplete message, wait for more data
		mgr->read_buffer = buf;
		return NULL;
	}

	//Framed a message, go ahead and parse
	struct ami_message *parsed_message = calloc(1, sizeof(struct ami_message));
	if (!parsed_message) {
		ast_log(LOG_ERROR, "Memory allocation failed\n");
		free(buf);
		return NULL;
	}

	parsed_message->type = parse_message_type(buf);
	if (parsed_message->type == UNKNOWN_MESSAGE) {
		free(buf);
		free(parsed_message);
		return NULL;
	}

	switch (parsed_message->type) {
		case EVENT_MESSAGE:
			parsed_message->event = parse_event(buf + 7);
			break;
		case RESPONSE_MESSAGE:
			parsed_message->response = parse_response(buf);
			break;
		default:
			ast_log(LOG_NOTICE, "Unknown data from AMI: [%s]\n", buf);
			break;
	}
	free(buf);

	return parsed_message;
}

/*
 * Called for each manager event and command response
 */
static int manager_hook_cb(int catergory, const char* event, char* content, void *caller_data)
{
	struct ami_message *message_tmp;
	struct ami_action *completed_action = NULL;
	struct ami *mgr = (struct ami *) caller_data;
	char c = '\0';

	ami_lock(mgr);

	//Parse content and create message
	struct ami_message *message = parse_data(mgr, content);
	if (!message) {
		//Unparsable or incomplete message
		ami_unlock(mgr);
		return -1;
	}

	//Handle response
	if (message->type == RESPONSE_MESSAGE && message->response) {
		/* Lookup pending action */
		completed_action = get_pending_action(mgr, message->response->id);

		if (completed_action) {
			/* Move user data */
			message->response->userdata = completed_action->userdata;
			completed_action->userdata = NULL;

			free(completed_action);
			completed_action = NULL;
		}
		else {
			ast_log(LOG_ERROR, "No pending action stored for received manager response (id: 0x%x)\n", message->response->id);
		}
	}

	//Push parsed message on in_queue
	if (mgr->in_queue) {
		message_tmp = mgr->in_queue;
		while (message_tmp->next) {
			message_tmp = message_tmp->next;
		}
		message_tmp->next = message;
	}
	else {
		mgr->in_queue = message;
	}

	//Notify client that new data is available
	if (write(mgr->fd, &c, sizeof(char)) < 0) {
		ast_log(LOG_ERROR, "Failed to notify listener: %s\n", strerror(errno));
	}

	ami_unlock(mgr);
	return 0;
}
