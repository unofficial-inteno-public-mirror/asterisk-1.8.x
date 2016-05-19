/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2010, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief General Asterisk locking by hacking. We have got problems
 * with pthreads locking in Asterisk on MIPS. While we investigate
 * the cause a replacement locking mechanism has been implemented,
 * fully replacing phtreads locking. This is for temporary use only!!!!!
 * /Ronny
 */

#ifdef _MIPS_ARCH
#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 314358 $")

#include "asterisk/lock.h"

#if defined(__linux__) && !defined(__NR_gettid)
#include <asm/unistd.h>
#endif




//-------------------------------------------------------------
static int ronny_mutex_lock(const char *filename, int lineno, const char *func,
		const char* mutex_name, ast_mutex_t *t, int blockWait)
{
	pid_t tid = syscall(__NR_gettid);
	__sync_synchronize();

	// Contend for the lock
	if(t->mutex.owner != tid || t->mutex.owner != tid) {						// Read twice yes, it's volatile
		if(blockWait) {
			while(!__sync_bool_compare_and_swap(&t->mutex.doubleLock, 0, 1)) {	// Blocking wait for busy lock
				usleep(1900);
			}
		}
		else if(!__sync_bool_compare_and_swap(&t->mutex.doubleLock, 0, 1)) {
			// Lock was busy but don't wait for it return immediately
			errno = EBUSY;
			return -1;
		}
	}

	if(t->mutex.owner == 0 || t->mutex.owner == tid) {
		// We have got the lock! Mark ourself as owner.
		t->mutex.lock = 1;
		t->mutex.owner = tid;
		t->mutex.count++;														// Increase ref count (recursive lock)
		__sync_synchronize();
	}

	/* Both belt and suspenders, sanity check the locks
	 * again. This loop should never occur. */
	while(!t->mutex.lock || !t->mutex.doubleLock || !t->mutex.count ||
			t->mutex.owner != tid) {
		printf("ronny_mutex_lock() thread %lx tid %ld invalid exit lockId %p, lock %x, double %d, count %x, owner %ld\n",
			pthread_self(), tid, &t->mutex, t->mutex.lock, t->mutex.doubleLock,
			t->mutex.count, t->mutex.owner);
		fflush(NULL);
		usleep(100000);
	}

	return 0;
}



//-------------------------------------------------------------
static int ronny_mutex_unlock(const char *filename, int lineno, const char *func,
		const char *mutex_name, ast_mutex_t *t) {
	pid_t tid = syscall(__NR_gettid);
	__sync_synchronize();

	/* Sanity check of the lock. This invalid
	 * state should never occur. */
	while(!t->mutex.lock || !t->mutex.doubleLock || t->mutex.owner != tid) {
		printf("ronny_mutex_unlock() thread %lx tid %ld invalid owner unlockId %p, lock %x, double %d, count %x, owner %ld\n",
			pthread_self(), tid, &t->mutex, t->mutex.lock, t->mutex.doubleLock,
			t->mutex.count, t->mutex.owner);
		fflush(NULL);
		usleep(100000);
	}

	pthread_yield();
	if(t->mutex.count) t->mutex.count--;										// Decrease ref count (recursive lock)
	if(t->mutex.count == 0) {
		t->mutex.owner = 0;
		t->mutex.lock = 0;

		// Lock release. Should never fail.
		if(!__sync_bool_compare_and_swap(&t->mutex.doubleLock, 1, 0)) {
			printf("ronny_mutex_unlock() thread %lx tid %ld failed double unlockId %p\n",
				pthread_self(), tid, &t->mutex);
			fflush(NULL);
			while(1) usleep(0);
		}
	}

	return 0;
}



//-------------------------------------------------------------
int __ast_pthread_mutex_init(int tracking, const char *filename, int lineno,
		const char *func, const char *mutex_name, ast_mutex_t *t)
{
	int i;
	pid_t tid = syscall(__NR_gettid);

	memset(&t->mutex, 0, sizeof(struct ronny_mutex_t));
	for(i = 0; i < sizeof(t->mutex.protector1); i++) t->mutex.protector1[i] = i+1;
	t->mutex.count = 0;
	t->mutex.owner = 0;
	t->mutex.lock = 0;

	return 0;
}



//-------------------------------------------------------------
int __ast_pthread_mutex_destroy(const char *filename, int lineno, const char *func,
		const char *mutex_name, ast_mutex_t *t) {
	pid_t tid = syscall(__NR_gettid);

	// Check that lock has been released before destruction
	while(t->mutex.lock && t->mutex.owner == tid) {
		printf("Ronny ast_pthread_mutex_destroy() thread %lx tid %ld invalid destroy lockId %p, lock %x, count %x, owner %ld\n",
			pthread_self(), tid, &t->mutex, t->mutex.lock, t->mutex.count,
			t->mutex.owner);
		usleep(100000);
		fflush(NULL);
	}

	return 0;
}


int __ast_pthread_mutex_lock(const char *filename, int lineno, const char *func,
		const char* mutex_name, ast_mutex_t *t) {
	return ronny_mutex_lock(filename, lineno, func, mutex_name, t, 1);
}



int __ast_pthread_mutex_trylock(const char *filename, int lineno, const char *func,
		const char* mutex_name, ast_mutex_t *t) {
	return ronny_mutex_lock(filename, lineno, func, mutex_name, t, 0);
}



int __ast_pthread_mutex_unlock(const char *filename, int lineno, const char *func,
		const char *mutex_name, ast_mutex_t *t) {
	return ronny_mutex_unlock(filename, lineno, func, mutex_name, t);
}



int __ast_cond_init(const char *filename, int lineno, const char *func,
		const char *cond_name, ast_cond_t *cond, pthread_condattr_t *cond_attr)
{
	cond->wake = 0;
	return 0;
}


int __ast_cond_signal(const char *filename, int lineno, const char *func,
				    const char *cond_name, ast_cond_t *cond)
{
	pthread_yield();
	while(!cond->wake) {
		cond->wake = 1;
		pthread_yield();
		usleep(0);
	}
	return 0;
}


int __ast_cond_broadcast(const char *filename, int lineno, const char *func,
				       const char *cond_name, ast_cond_t *cond)
{
	return __ast_cond_signal(filename, lineno, func, cond_name, cond);
}


int __ast_cond_destroy(const char *filename, int lineno, const char *func,
				     const char *cond_name, ast_cond_t *cond)
{
	return 0;
}


int __ast_cond_wait(const char *filename, int lineno, const char *func,
		const char *cond_name, const char *mutex_name, ast_cond_t *cond,
		ast_mutex_t *t)
{
	ronny_mutex_unlock(filename, lineno, func, mutex_name, t);

	pthread_yield();
	while(cond->wake) {
		cond->wake = 0;
		pthread_yield();
		pthread_yield();
		usleep(0);
		pthread_yield();
		usleep(0);
	}
	
	while(!cond->wake) {
		pthread_yield();
		usleep(0);
	}

	return ronny_mutex_lock(filename, lineno, func, cond_name, t, 1);
}


int __ast_cond_timedwait(const char *filename, int lineno, const char *func,
		const char *cond_name, const char *mutex_name, ast_cond_t *cond,
		ast_mutex_t *t, const struct timespec *abstime)
{
	return __ast_cond_wait(filename, lineno, func, cond_name,
		mutex_name, cond, t);
}


int __ast_rwlock_init(int tracking, const char *filename, int lineno,
		const char *func, const char *rwlock_name, ast_rwlock_t *t) {
	return __ast_pthread_mutex_init(tracking, filename, lineno, func,
		rwlock_name, (ast_mutex_t*) t);
}


int __ast_rwlock_destroy(const char *filename, int lineno, const char *func,
		const char *rwlock_name, ast_rwlock_t *t) {
	pid_t tid = syscall(__NR_gettid);

	// Check that lock has been released before destruction
	while(t->mutex.lock && t->mutex.owner == tid) {
		printf("Ronny ast_rwlock_destroy() thread %lx tid %ld invalid destroy lockId %p, lock %x, count %x, owner %ld\n",
			pthread_self(), tid, &t->mutex, t->mutex.lock, t->mutex.count,
			t->mutex.owner);
		usleep(100000);
		fflush(NULL);
	}

	return 0;
}


int __ast_rwlock_unlock(const char *filename, int line, const char *func,
		ast_rwlock_t *t, const char *name) {
	return ronny_mutex_unlock(filename, line, func, name, t);
}


int __ast_rwlock_rdlock(const char *filename, int line, const char *func,
		ast_rwlock_t *t, const char *name) {
	return ronny_mutex_lock(filename, line, func, name,  (ast_mutex_t*) t, 1);
}


int __ast_rwlock_wrlock(const char *filename, int line, const char *func,
		ast_rwlock_t *t, const char *name) {
	return ronny_mutex_lock(filename, line, func, name, (ast_mutex_t*) t, 1);
}


int __ast_rwlock_timedrdlock(const char *filename, int line, const char *func,
		ast_rwlock_t *t, const char *name, const struct timespec *abs_timeout) {
	return __ast_rwlock_rdlock(filename, line, func, (ast_mutex_t*) t, name);
}


int __ast_rwlock_timedwrlock(const char *filename, int line, const char *func,
		ast_rwlock_t *t, const char *name, const struct timespec *abs_timeout) {
	return __ast_rwlock_wrlock(filename, line, func, (ast_mutex_t*) t, name);
}


int __ast_rwlock_tryrdlock(const char *filename, int line, const char *func,
		ast_rwlock_t *t, const char *name) {
	return ronny_mutex_lock(filename, line, func, name, (ast_mutex_t*) t, 0);
}


int __ast_rwlock_trywrlock(const char *filename, int line, const char *func,
		ast_rwlock_t *t, const char *name) {
	return ronny_mutex_lock(filename, line, func, name, (ast_mutex_t*) t, 0);
}

#endif /* _MIPS_ARCH */
