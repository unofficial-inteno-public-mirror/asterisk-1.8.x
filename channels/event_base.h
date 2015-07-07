#ifndef EVENT_BASE_H
#define EVENT_BASE_H

void * event_base_new(int count);
void * event_base_add_stream(void * _self, void * stream);
void * event_base_delete_stream(void * _self, void * stream);
void * event_base_dispatch(void * _self);



#endif /* EVENT_BASE_H */
