/*
 * codec.c
 *
 *  Created on: Mar 11, 2015
 *      Author: kj
 */

#include "codec.h"
#include <stdlib.h>
#include <string.h>

struct codec *codec_create(void)
{
	struct codec *c = malloc(sizeof(struct codec));
	memset(c, 0, sizeof(struct codec));

	return c;
}

void codec_delete(struct codec *c)
{
	if (c->key) {
		free(c->key);
	}

	if (c->value) {
		free(c->value);
	}

	free(c);
}
