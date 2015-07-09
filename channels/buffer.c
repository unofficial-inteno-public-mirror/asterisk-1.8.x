#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buffer.h"
#include "error.h"


enum {
	NORMAL_STATE,
	WRAPPED_STATE,
};

buffer_t * buffer_new(int size) {

	buffer_t *b = (buffer_t *) calloc(sizeof(buffer_t), 1);

	if (!b) {
		exit_failure("malloc\n");
	}
	
	b->buf_start = calloc(size, 1);
	if (!b->buf_start) {
		exit_failure("malloc\n");
	}
	
	b->count = 0;
	b->buf_end = b->buf_start + size;
	b->buf_size = size;
	b->data_start = b->buf_start;
	b->data_end = b->buf_start;
	b->state = NORMAL_STATE;
	
	return b;
}


static int write_normal(buffer_t * self, uint8_t *input, int count) {

	/* Don't write beyond buffer boundary */
	if ( self->data_end + count > self->buf_end ) {
		count = self->buf_end - self->data_end;
	}

	memcpy(self->data_end, input, count);
	self->data_end += count;
	self->count += count;

	return count;
}


static int write_wrapped(buffer_t * self, uint8_t *input, int count) {

	/* Don't write beyond start of data */
	if ( self->data_end + count > self->data_start ) {
		count = self->data_start - self->data_end;
	}
		
	memcpy(self->data_end, input, count);
	self->data_end += count;
	self->count += count;

	return count;
}


static int read_normal(buffer_t * self, uint8_t *buf, int count) {

	/* Don't read beyond end of data */
	if ( count > self->count) {
		count = self->count;
	}

	memcpy(buf, self->data_start, count);
	self->data_start += count;
	self->count -= count;
	
	return count;
}

static int read_wrapped(buffer_t * self, uint8_t *buf, int count) {
	
	/* Don't read beyond end of buffer */
	if ( self->data_start + count > self->buf_end ) {
		count = self->buf_end - self->data_start;
	}
		
	memcpy(buf, self->data_start, count);
	self->data_start += count;
	self->count -= count;

	return count;
}


static int rewind_normal(buffer_t * self, int count) {

	/* Don't rewind beyond start of buffer */
	if ( self->data_start - count < self->buf_start ) {
		count = self->data_start - self->buf_start;
	} 
	
	self->data_start -= count;
	self->count += count;

	return count;
}


static int rewind_wrapped(buffer_t * self, int count) {

	/* Don't rewind beyond end of data */
	if ( self->data_start - count < self->data_end ) {
		count = self->data_start - self->data_end;
	}
	
	self->data_start -= count;
	self->count += count;

	return count;
}


int buffer_write(buffer_t * self, uint8_t *input, int count) {
	
	int written;

	if (self->count == self->buf_size) {
		return 0;
	}

	if ( self->state == NORMAL_STATE) {

		written = write_normal(self, input, count);

		if ( written < count && self->count < self->buf_size ) {

			/* Wrap the buffer */
			self->state = WRAPPED_STATE;
			self->data_end = self->buf_start;

			written += write_wrapped(self, input + written, count - written);
		}
	
	} else if (self->state == WRAPPED_STATE )  {

		written = write_wrapped(self, input, count);

		if ( written < count && self->count < self->buf_size ) {

			/* Wrap the buffer */
			self->state = NORMAL_STATE;
			self->data_end = self->buf_start;
			
			written += write_normal(self, input + written, count - written);
		}
	}

	//buffer_dump(self);
	return written;
}


int buffer_read(buffer_t * self, uint8_t *buf, int count) {

	int read;

	if ( self->state == NORMAL_STATE ) {

		read = read_normal(self, buf, count);
		
		if ( read < count && self->count > 0) {

			/* Wrap the buffer */
			self->state = WRAPPED_STATE;
			self->data_start = self->buf_start;
			
			read += read_wrapped(self, buf + read, count - read);
		}



	} else if (self->state == WRAPPED_STATE )  {

		read = read_wrapped(self, buf, count);
		
		if ( read < count && self->count > 0) {

			/* Wrap the buffer */
			self->state = NORMAL_STATE;
			self->data_start = self->buf_start;
			
			read += read_normal(self, buf + read, count - read);
		}

	} 

	//buffer_dump(self);
	return read;
}


int buffer_rewind(buffer_t * self, int count) {

	int rewinded;

	if ( self->state == NORMAL_STATE ) {
		
		rewinded = rewind_normal(self, count);

		if ( rewinded < count ) {

			/* Wrap the buffer */
			self->state = WRAPPED_STATE;
			self->data_start = self->buf_end;

			rewinded += rewind_wrapped(self, count - rewinded);
		}

	} else if (self->state == WRAPPED_STATE )  {		

		rewinded = rewind_wrapped(self, count);
		
		if ( rewinded < count ) {

			/* Wrap the buffer */
			self->state = NORMAL_STATE;
			self->data_start = self->buf_end;

			rewinded += rewind_normal(self, count - rewinded);
		}
	}

	//buffer_dump(self);
	return rewinded;
}


int buffer_find(buffer_t * self, uint8_t c) {
	
	/* int i; */

	/* /\* Do we have byte c in buffer? *\/ */
        /* for (i = 0; i < self->count - self->cursor; i++) { */
        /*         if (self->in[i + self->cursor] == c) { */
        /*                 return i; */
        /*         } */
        /*         return -1; */
        /* } */

}


int buffer_dump(buffer_t * self) {
	
	int i, j, data_start, data_end;
	
	data_start = self->data_start - self->buf_start;
	data_end = self->data_end - self->buf_start;

	printf("[BUFFER: count %d\t size %d] \n", self->count, self->buf_size);
	printf("[data_start %d\t data_end %d] \n", data_start, data_end);

	for (i = 0; i < self->buf_size; i++) {

		if ( i % 25 == 0 ) {
			printf("\n");
		}

		if ( i == data_start ) {
			printf("[");
		}

		if ( i == data_end ) {
			printf("]");
		}
		

		printf("%02x ", self->buf_start[i]);
	}
	printf("\n\n");


}


int buffer_size(buffer_t * self) {

	return self->count;
}
