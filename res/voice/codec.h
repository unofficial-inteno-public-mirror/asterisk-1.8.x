/*
 * codec.h
 *
 *  Created on: Mar 11, 2015
 *      Author: kj
 */

#ifndef CODEC_H_
#define CODEC_H_

struct codec {
  char *key;
  char *value;
  unsigned int bitrate;
  struct codec *next;
};

struct codec *codec_create(void);
void codec_delete(struct codec *codec);

#endif /* CODEC_H_ */
