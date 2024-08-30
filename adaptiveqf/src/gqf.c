#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "hashutil.h"
#include "gqf.h"
#include "gqf_int.h"
#include "ll_table.h"

/******************************************************************
 * Code for managing the metadata bits and slots w/o interpreting *
 * the content of the slots.
 ******************************************************************/

#define METADATA_INC_MODE 1 // 0 for no inc, 1 for direct in, 2 for pc inc

#define MAX_VALUE(nbits) ((1ULL << (nbits)) - 1)
#define BITMASK(nbits)                                    \
  ((nbits) == 64 ? 0xffffffffffffffff : MAX_VALUE(nbits))
#define NUM_SLOTS_TO_LOCK (1ULL<<16)
#define CLUSTER_SIZE (1ULL<<14)
#define METADATA_WORD(qf,field,slot_index)                              \
  (get_block((qf), (slot_index) /                                       \
             QF_SLOTS_PER_BLOCK)->field[((slot_index)  % QF_SLOTS_PER_BLOCK) / 64])

#define GET_NO_LOCK(flag) (flag & QF_NO_LOCK)
#define GET_TRY_ONCE_LOCK(flag) (flag & QF_TRY_ONCE_LOCK)
#define GET_WAIT_FOR_LOCK(flag) (flag & QF_WAIT_FOR_LOCK)
#define GET_KEY_HASH(flag) (flag & QF_KEY_IS_HASH)

#define DISTANCE_FROM_HOME_SLOT_CUTOFF 1000
#define BILLION 1000000000L

#define GET_REMAINDER(qf, idx) (get_slot(qf, idx) & BITMASK(qf->metadata->key_remainder_bits))
#define GET_FIRST_EXTENSION(qf, idx) ((get_slot(qf, idx) >> qf->metadata->key_remainder_bits) & BITMASK(qf->metadata->value_bits))

#ifdef DEBUG
#define PRINT_DEBUG 1
#else
#define PRINT_DEBUG 0
#endif

#define DEBUG_CQF(fmt, ...) \
	do { if (PRINT_DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)

#define DEBUG_DUMP(qf) \
	do { if (PRINT_DEBUG) qf_dump_metadata(qf); } while (0)

void bp1(const QF *qf, uint64_t hash_bucket_index, uint64_t hash_bucket_offset, uint64_t hash_remainder) {
	return;
}

static __inline__ unsigned long long rdtsc(void)
{
	unsigned hi, lo;
	__asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
	return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}

#ifdef LOG_WAIT_TIME
static inline bool qf_spin_lock(QF *qf, volatile int *lock, uint64_t idx,
																uint8_t flag)
{
	struct timespec start, end;
	bool ret;

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
	if (GET_WAIT_FOR_LOCK(flag) != QF_WAIT_FOR_LOCK) {
		ret = !__sync_lock_test_and_set(lock, 1);
		clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
		qf->runtimedata->wait_times[idx].locks_acquired_single_attempt++;
		qf->runtimedata->wait_times[idx].total_time_single += BILLION * (end.tv_sec -
																												start.tv_sec) +
			end.tv_nsec - start.tv_nsec;
	} else {
		if (!__sync_lock_test_and_set(lock, 1)) {
			clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
			qf->runtimedata->wait_times[idx].locks_acquired_single_attempt++;
			qf->runtimedata->wait_times[idx].total_time_single += BILLION * (end.tv_sec -
																													start.tv_sec) +
			end.tv_nsec - start.tv_nsec;
		} else {
			while (__sync_lock_test_and_set(lock, 1))
				while (*lock);
			clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
			qf->runtimedata->wait_times[idx].total_time_spinning += BILLION * (end.tv_sec -
																														start.tv_sec) +
				end.tv_nsec - start.tv_nsec;
		}
		ret = true;
	}
	qf->runtimedata->wait_times[idx].locks_taken++;

	return ret;

	/*start = rdtsc();*/
	/*if (!__sync_lock_test_and_set(lock, 1)) {*/
		/*clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);*/
		/*qf->runtimedata->wait_times[idx].locks_acquired_single_attempt++;*/
		/*qf->runtimedata->wait_times[idx].total_time_single += BILLION * (end.tv_sec -
		 * start.tv_sec) + end.tv_nsec - start.tv_nsec;*/
	/*} else {*/
		/*while (__sync_lock_test_and_set(lock, 1))*/
			/*while (*lock);*/
		/*clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);*/
		/*qf->runtimedata->wait_times[idx].total_time_spinning += BILLION * (end.tv_sec -
		 * start.tv_sec) + end.tv_nsec - start.tv_nsec;*/
	/*}*/

	/*end = rdtsc();*/
	/*qf->runtimedata->wait_times[idx].locks_taken++;*/
	/*return;*/
}
#else
/**
 * Try to acquire a lock once and return even if the lock is busy.
 * If spin flag is set, then spin until the lock is available.
 */
static inline bool qf_spin_lock(volatile int *lock, uint8_t flag)
{
	if (GET_WAIT_FOR_LOCK(flag) != QF_WAIT_FOR_LOCK) {
		return !__sync_lock_test_and_set(lock, 1);
	} else {
		while (__sync_lock_test_and_set(lock, 1))
			while (*lock);
		return true;
	}

	return false;
}
#endif

static inline void qf_spin_unlock(volatile int *lock)
{
	__sync_lock_release(lock);
	return;
}

bool qf_lock(QF *qf, uint64_t hash_bucket_index, bool small, uint8_t
										runtime_lock)
{
	uint64_t hash_bucket_lock_offset  = hash_bucket_index % NUM_SLOTS_TO_LOCK;
	if (small) {
#ifdef LOG_WAIT_TIME
		if (!qf_spin_lock(qf, &qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK],
											hash_bucket_index/NUM_SLOTS_TO_LOCK,
											runtime_lock))
			return false;
		if (NUM_SLOTS_TO_LOCK - hash_bucket_lock_offset <= CLUSTER_SIZE) {
			if (!qf_spin_lock(qf, &qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK+1],
												hash_bucket_index/NUM_SLOTS_TO_LOCK+1,
												runtime_lock)) {
				qf_spin_unlock(&qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK]);
				return false;
			}
		}
#else
		if (!qf_spin_lock(&qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK],
											runtime_lock))
			return false;
		if (NUM_SLOTS_TO_LOCK - hash_bucket_lock_offset <= CLUSTER_SIZE) {
			if (!qf_spin_lock(&qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK+1],
												runtime_lock)) {
				qf_spin_unlock(&qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK]);
				return false;
			}
		}
#endif
	} else {
#ifdef LOG_WAIT_TIME
		if (hash_bucket_index >= NUM_SLOTS_TO_LOCK && hash_bucket_lock_offset <=
				CLUSTER_SIZE) {
			if (!qf_spin_lock(qf,
												&qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK-1],
												runtime_lock))
				return false;
		}
		if (!qf_spin_lock(qf,
											&qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK],
											runtime_lock)) {
			if (hash_bucket_index >= NUM_SLOTS_TO_LOCK && hash_bucket_lock_offset <=
					CLUSTER_SIZE)
				qf_spin_unlock(&qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK-1]);
			return false;
		}
		if (!qf_spin_lock(qf, &qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK+1],
											runtime_lock)) {
			qf_spin_unlock(&qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK]);
			if (hash_bucket_index >= NUM_SLOTS_TO_LOCK && hash_bucket_lock_offset <=
					CLUSTER_SIZE)
				qf_spin_unlock(&qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK-1]);
			return false;
		}
#else
		if (hash_bucket_index >= NUM_SLOTS_TO_LOCK && hash_bucket_lock_offset <=
				CLUSTER_SIZE) {
			if
				(!qf_spin_lock(&qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK-1],
											 runtime_lock))
				return false;
		}
		if (!qf_spin_lock(&qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK],
											runtime_lock)) {
			if (hash_bucket_index >= NUM_SLOTS_TO_LOCK && hash_bucket_lock_offset <=
					CLUSTER_SIZE)
				qf_spin_unlock(&qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK-1]);
			return false;
		}
		if (!qf_spin_lock(&qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK+1],
											runtime_lock)) {
			qf_spin_unlock(&qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK]);
			if (hash_bucket_index >= NUM_SLOTS_TO_LOCK && hash_bucket_lock_offset <=
					CLUSTER_SIZE)
				qf_spin_unlock(&qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK-1]);
			return false;
		}
#endif
	}
	return true;
}

void qf_unlock(QF *qf, uint64_t hash_bucket_index, bool small)
{
	uint64_t hash_bucket_lock_offset  = hash_bucket_index % NUM_SLOTS_TO_LOCK;
	if (small) {
		if (NUM_SLOTS_TO_LOCK - hash_bucket_lock_offset <= CLUSTER_SIZE) {
			qf_spin_unlock(&qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK+1]);
		}
		qf_spin_unlock(&qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK]);
	} else {
		qf_spin_unlock(&qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK+1]);
		qf_spin_unlock(&qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK]);
		if (hash_bucket_index >= NUM_SLOTS_TO_LOCK && hash_bucket_lock_offset <=
				CLUSTER_SIZE)
			qf_spin_unlock(&qf->runtimedata->locks[hash_bucket_index/NUM_SLOTS_TO_LOCK-1]);
	}
}

/*static void modify_metadata(QF *qf, uint64_t *metadata, int cnt)*/
/*{*/
/*#ifdef LOG_WAIT_TIME*/
	/*qf_spin_lock(qf, &qf->runtimedata->metadata_lock,*/
							 /*qf->runtimedata->num_locks, QF_WAIT_FOR_LOCK);*/
/*#else*/
	/*qf_spin_lock(&qf->runtimedata->metadata_lock, QF_WAIT_FOR_LOCK);*/
/*#endif*/
	/**metadata = *metadata + cnt;*/
	/*qf_spin_unlock(&qf->runtimedata->metadata_lock);*/
	/*return;*/
/*}*/

static void modify_metadata(pc_t *metadata, int cnt)
{
	pc_add(metadata, cnt);
	return;
}

static inline int popcnt(uint64_t val)
{
	asm("popcnt %[val], %[val]"
			: [val] "+r" (val)
			:
			: "cc");
	return val;
}

static inline int64_t bitscanreverse(uint64_t val)
{
	if (val == 0) {
		return -1;
	} else {
		asm("bsr %[val], %[val]"
				: [val] "+r" (val)
				:
				: "cc");
		return val;
	}
}

static inline int popcntv(const uint64_t val, int ignore)
{
	if (ignore % 64)
		return popcnt (val & ~BITMASK(ignore % 64));
	else
		return popcnt(val);
}

// Returns the number of 1s up to (and including) the pos'th bit
// Bits are numbered from 0
static inline int bitrank(uint64_t val, int pos) {
	val = val & ((2ULL << pos) - 1);
	asm("popcnt %[val], %[val]"
			: [val] "+r" (val)
			:
			: "cc");
	return val;
}

/**
 * Returns the position of the k-th 1 in the 64-bit word x.
 * k is 0-based, so k=0 returns the position of the first 1.
 *
 * Uses the broadword selection algorithm by Vigna [1], improved by Gog
 * and Petri [2] and Vigna [3].
 *
 * [1] Sebastiano Vigna. Broadword Implementation of Rank/Select
 *    Queries. WEA, 2008
 *
 * [2] Simon Gog, Matthias Petri. Optimized succinct data
 * structures for massive data. Softw. Pract. Exper., 2014
 *
 * [3] Sebastiano Vigna. MG4J 5.2.1. http://mg4j.di.unimi.it/
 * The following code is taken from
 * https://github.com/facebook/folly/blob/b28186247104f8b90cfbe094d289c91f9e413317/folly/experimental/Select64.h
 */
const uint8_t kSelectInByte[2048] = {
	8, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0,
	1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0,
	2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0,
	1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0,
	3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 7, 0,
	1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0,
	2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0,
	1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
	4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0,
	1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 8, 8, 8, 1,
	8, 2, 2, 1, 8, 3, 3, 1, 3, 2, 2, 1, 8, 4, 4, 1, 4, 2, 2, 1, 4, 3, 3, 1, 3, 2,
	2, 1, 8, 5, 5, 1, 5, 2, 2, 1, 5, 3, 3, 1, 3, 2, 2, 1, 5, 4, 4, 1, 4, 2, 2, 1,
	4, 3, 3, 1, 3, 2, 2, 1, 8, 6, 6, 1, 6, 2, 2, 1, 6, 3, 3, 1, 3, 2, 2, 1, 6, 4,
	4, 1, 4, 2, 2, 1, 4, 3, 3, 1, 3, 2, 2, 1, 6, 5, 5, 1, 5, 2, 2, 1, 5, 3, 3, 1,
	3, 2, 2, 1, 5, 4, 4, 1, 4, 2, 2, 1, 4, 3, 3, 1, 3, 2, 2, 1, 8, 7, 7, 1, 7, 2,
	2, 1, 7, 3, 3, 1, 3, 2, 2, 1, 7, 4, 4, 1, 4, 2, 2, 1, 4, 3, 3, 1, 3, 2, 2, 1,
	7, 5, 5, 1, 5, 2, 2, 1, 5, 3, 3, 1, 3, 2, 2, 1, 5, 4, 4, 1, 4, 2, 2, 1, 4, 3,
	3, 1, 3, 2, 2, 1, 7, 6, 6, 1, 6, 2, 2, 1, 6, 3, 3, 1, 3, 2, 2, 1, 6, 4, 4, 1,
	4, 2, 2, 1, 4, 3, 3, 1, 3, 2, 2, 1, 6, 5, 5, 1, 5, 2, 2, 1, 5, 3, 3, 1, 3, 2,
	2, 1, 5, 4, 4, 1, 4, 2, 2, 1, 4, 3, 3, 1, 3, 2, 2, 1, 8, 8, 8, 8, 8, 8, 8, 2,
	8, 8, 8, 3, 8, 3, 3, 2, 8, 8, 8, 4, 8, 4, 4, 2, 8, 4, 4, 3, 4, 3, 3, 2, 8, 8,
	8, 5, 8, 5, 5, 2, 8, 5, 5, 3, 5, 3, 3, 2, 8, 5, 5, 4, 5, 4, 4, 2, 5, 4, 4, 3,
	4, 3, 3, 2, 8, 8, 8, 6, 8, 6, 6, 2, 8, 6, 6, 3, 6, 3, 3, 2, 8, 6, 6, 4, 6, 4,
	4, 2, 6, 4, 4, 3, 4, 3, 3, 2, 8, 6, 6, 5, 6, 5, 5, 2, 6, 5, 5, 3, 5, 3, 3, 2,
	6, 5, 5, 4, 5, 4, 4, 2, 5, 4, 4, 3, 4, 3, 3, 2, 8, 8, 8, 7, 8, 7, 7, 2, 8, 7,
	7, 3, 7, 3, 3, 2, 8, 7, 7, 4, 7, 4, 4, 2, 7, 4, 4, 3, 4, 3, 3, 2, 8, 7, 7, 5,
	7, 5, 5, 2, 7, 5, 5, 3, 5, 3, 3, 2, 7, 5, 5, 4, 5, 4, 4, 2, 5, 4, 4, 3, 4, 3,
	3, 2, 8, 7, 7, 6, 7, 6, 6, 2, 7, 6, 6, 3, 6, 3, 3, 2, 7, 6, 6, 4, 6, 4, 4, 2,
	6, 4, 4, 3, 4, 3, 3, 2, 7, 6, 6, 5, 6, 5, 5, 2, 6, 5, 5, 3, 5, 3, 3, 2, 6, 5,
	5, 4, 5, 4, 4, 2, 5, 4, 4, 3, 4, 3, 3, 2, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 3, 8, 8, 8, 8, 8, 8, 8, 4, 8, 8, 8, 4, 8, 4, 4, 3, 8, 8, 8, 8, 8, 8,
	8, 5, 8, 8, 8, 5, 8, 5, 5, 3, 8, 8, 8, 5, 8, 5, 5, 4, 8, 5, 5, 4, 5, 4, 4, 3,
	8, 8, 8, 8, 8, 8, 8, 6, 8, 8, 8, 6, 8, 6, 6, 3, 8, 8, 8, 6, 8, 6, 6, 4, 8, 6,
	6, 4, 6, 4, 4, 3, 8, 8, 8, 6, 8, 6, 6, 5, 8, 6, 6, 5, 6, 5, 5, 3, 8, 6, 6, 5,
	6, 5, 5, 4, 6, 5, 5, 4, 5, 4, 4, 3, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 7, 8, 7,
	7, 3, 8, 8, 8, 7, 8, 7, 7, 4, 8, 7, 7, 4, 7, 4, 4, 3, 8, 8, 8, 7, 8, 7, 7, 5,
	8, 7, 7, 5, 7, 5, 5, 3, 8, 7, 7, 5, 7, 5, 5, 4, 7, 5, 5, 4, 5, 4, 4, 3, 8, 8,
	8, 7, 8, 7, 7, 6, 8, 7, 7, 6, 7, 6, 6, 3, 8, 7, 7, 6, 7, 6, 6, 4, 7, 6, 6, 4,
	6, 4, 4, 3, 8, 7, 7, 6, 7, 6, 6, 5, 7, 6, 6, 5, 6, 5, 5, 3, 7, 6, 6, 5, 6, 5,
	5, 4, 6, 5, 5, 4, 5, 4, 4, 3, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 4, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 5, 8, 8, 8, 8, 8, 8, 8, 5, 8, 8, 8, 5, 8, 5, 5, 4, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 6, 8, 8, 8, 8, 8, 8, 8, 6, 8, 8, 8, 6, 8, 6,
	6, 4, 8, 8, 8, 8, 8, 8, 8, 6, 8, 8, 8, 6, 8, 6, 6, 5, 8, 8, 8, 6, 8, 6, 6, 5,
	8, 6, 6, 5, 6, 5, 5, 4, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8,
	8, 8, 8, 8, 8, 7, 8, 8, 8, 7, 8, 7, 7, 4, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 7,
	8, 7, 7, 5, 8, 8, 8, 7, 8, 7, 7, 5, 8, 7, 7, 5, 7, 5, 5, 4, 8, 8, 8, 8, 8, 8,
	8, 7, 8, 8, 8, 7, 8, 7, 7, 6, 8, 8, 8, 7, 8, 7, 7, 6, 8, 7, 7, 6, 7, 6, 6, 4,
	8, 8, 8, 7, 8, 7, 7, 6, 8, 7, 7, 6, 7, 6, 6, 5, 8, 7, 7, 6, 7, 6, 6, 5, 7, 6,
	6, 5, 6, 5, 5, 4, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 5, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 6, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 6, 8, 8, 8, 8, 8, 8, 8, 6, 8, 8, 8, 6,
	8, 6, 6, 5, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 7,
	8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 7, 8, 7, 7, 5, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 7, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 7, 8, 7, 7, 6, 8, 8, 8, 8,
	8, 8, 8, 7, 8, 8, 8, 7, 8, 7, 7, 6, 8, 8, 8, 7, 8, 7, 7, 6, 8, 7, 7, 6, 7, 6,
	6, 5, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 6,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 7, 8, 7, 7, 6, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 7
};

static inline uint64_t _select64(uint64_t x, int k)
{
	if (k >= popcnt(x)) { return 64; }
	
	const uint64_t kOnesStep4  = 0x1111111111111111ULL;
	const uint64_t kOnesStep8  = 0x0101010101010101ULL;
	const uint64_t kMSBsStep8  = 0x80ULL * kOnesStep8;

	uint64_t s = x;
	s = s - ((s & 0xA * kOnesStep4) >> 1);
	s = (s & 0x3 * kOnesStep4) + ((s >> 2) & 0x3 * kOnesStep4);
	s = (s + (s >> 4)) & 0xF * kOnesStep8;
	uint64_t byteSums = s * kOnesStep8;

	uint64_t kStep8 = k * kOnesStep8;
	uint64_t geqKStep8 = (((kStep8 | kMSBsStep8) - byteSums) & kMSBsStep8);
	uint64_t place = popcnt(geqKStep8) * 8;
	uint64_t byteRank = k - (((byteSums << 8) >> place) & (uint64_t)(0xFF));
	return place + kSelectInByte[((x >> place) & 0xFF) | (byteRank << 8)];
}

// Returns the position of the rank'th 1.  (rank = 0 returns the 1st 1)
// Returns 64 if there are fewer than rank+1 1s.
static inline uint64_t bitselect(uint64_t val, int rank) {
#ifdef __SSE4_2_
	uint64_t i = 1ULL << rank;
	asm("pdep %[val], %[mask], %[val]" : [val] "+r" (val) : [mask] "r" (i));
	asm("tzcnt %[bit], %[index]" : [index] "=r" (i) : [bit] "g" (val) : "cc");
	return i;
#endif
	return _select64(val, rank);
}

static inline uint64_t bitselectv(const uint64_t val, int ignore, int rank)
{
	return bitselect(val & ~BITMASK(ignore % 64), rank);
}

static inline int is_keepsake_or_quotient_runend(const QF *qf, uint64_t index)
{
	return  (METADATA_WORD(qf, runends, index) >> ((index % QF_SLOTS_PER_BLOCK) % 64)) & 1ULL;
}

static inline int is_runend(const QF *qf, uint64_t index)
{
	return ~(METADATA_WORD(qf, extensions, index) >> ((index % QF_SLOTS_PER_BLOCK) % 64)) & 
	(METADATA_WORD(qf, runends, index) >> ((index % QF_SLOTS_PER_BLOCK) % 64)) & 1ULL;
	//return (METADATA_WORD(qf, runends, index) >> ((index % QF_SLOTS_PER_BLOCK) % 64)) & 1ULL;
}

static inline int is_occupied(const QF *qf, uint64_t index)
{
	return (METADATA_WORD(qf, occupieds, index) >> ((index % QF_SLOTS_PER_BLOCK) % 64)) & 1ULL;
}

static inline int is_extension(const QF *qf, uint64_t index)
{
	return (METADATA_WORD(qf, extensions, index) >> ((index % QF_SLOTS_PER_BLOCK) % 64)) & 
	~(METADATA_WORD(qf, runends, index) >> ((index % QF_SLOTS_PER_BLOCK) % 64)) & 1ULL;
	//return (METADATA_WORD(qf, extensions, index) >> ((index % QF_SLOTS_PER_BLOCK) % 64)) & 1ULL;
}

static inline int is_counter(const QF *qf, uint64_t index)
{
	return (METADATA_WORD(qf, extensions, index) >> ((index % QF_SLOTS_PER_BLOCK) % 64)) & 
	(METADATA_WORD(qf, runends, index) >> ((index % QF_SLOTS_PER_BLOCK) % 64)) & 1ULL;
	//return 0;
}

static inline int is_runend_or_counter(const QF *qf, uint64_t index)
{
	return (METADATA_WORD(qf, runends, index) >> ((index % QF_SLOTS_PER_BLOCK) & 0b111111)) & 1ULL;
}

static inline int is_extension_or_counter(const QF *qf, uint64_t index)
{
	return (METADATA_WORD(qf, extensions, index) >> ((index % QF_SLOTS_PER_BLOCK) & 0b111111)) & 1ULL;
}

static inline int bp()
{
	return 0;
}

#if QF_BITS_PER_SLOT == 8 || QF_BITS_PER_SLOT == 16 || QF_BITS_PER_SLOT == 32 || QF_BITS_PER_SLOT == 64

static inline uint64_t get_slot(const QF *qf, uint64_t index)
{	
	//printf("index%lu\n", index);
	assert(index < qf->metadata->xnslots);
	return get_block(qf, index / QF_SLOTS_PER_BLOCK)->slots[index % QF_SLOTS_PER_BLOCK];
}

static inline void set_slot(const QF *qf, uint64_t index, uint64_t value)
{
	assert(index < qf->metadata->xnslots);
	get_block(qf, index / QF_SLOTS_PER_BLOCK)->slots[index % QF_SLOTS_PER_BLOCK] =
		value & BITMASK(qf->metadata->bits_per_slot);
}

#elif QF_BITS_PER_SLOT > 0

/* Little-endian code ....  Big-endian is TODO */

static inline uint64_t get_slot(const QF *qf, uint64_t index)
{
	/* Should use __uint128_t to support up to 64-bit remainders, but gcc seems
	 * to generate buggy code.  :/  */
	//printf("index%lu\n", index);
	assert(index < qf->metadata->xnslots);
	uint64_t *p = (uint64_t *)&get_block(qf, index /
																			 QF_SLOTS_PER_BLOCK)->slots[(index %
																																QF_SLOTS_PER_BLOCK)
																			 * QF_BITS_PER_SLOT / 8];
	return (uint64_t)(((*p) >> (((index % QF_SLOTS_PER_BLOCK) * QF_BITS_PER_SLOT) %
															8)) & BITMASK(QF_BITS_PER_SLOT));
}

static inline void set_slot(const QF *qf, uint64_t index, uint64_t value)
{
	/* Should use __uint128_t to support up to 64-bit remainders, but gcc seems
	 * to generate buggy code.  :/  */
	assert(index < qf->metadata->xnslots);
	uint64_t *p = (uint64_t *)&get_block(qf, index /
																			 QF_SLOTS_PER_BLOCK)->slots[(index %
																																QF_SLOTS_PER_BLOCK)
																			 * QF_BITS_PER_SLOT / 8];
	uint64_t t = *p;
	uint64_t mask = BITMASK(QF_BITS_PER_SLOT);
	uint64_t v = value;
	int shift = ((index % QF_SLOTS_PER_BLOCK) * QF_BITS_PER_SLOT) % 8;
	mask <<= shift;
	v <<= shift;
	t &= ~mask;
	t |= v;
	*p = t;
}

#else

/* Little-endian code ....  Big-endian is TODO */

static inline uint64_t get_slot(const QF *qf, uint64_t index)
{	
	if (index > qf->metadata->xnslots) {
		bp();
		//printf("filter is full\n");
		return QF_NO_SPACE;
	}
	//printf("index %lu\n", index);
	assert(index < qf->metadata->xnslots);
	/* Should use __uint128_t to support up to 64-bit remainders, but gcc seems
	 * to generate buggy code.  :/  */
	uint64_t *p = (uint64_t *)&get_block(qf, index /
																			 QF_SLOTS_PER_BLOCK)->slots[(index %
																																QF_SLOTS_PER_BLOCK)
																			 * qf->metadata->bits_per_slot / 8];
	return (uint64_t)(((*p) >> (((index % QF_SLOTS_PER_BLOCK) *
															 qf->metadata->bits_per_slot) % 8)) &
										BITMASK(qf->metadata->bits_per_slot));
}

static inline void set_slot(const QF *qf, uint64_t index, uint64_t value)
{
	assert(index < qf->metadata->xnslots);
	/* Should use __uint128_t to support up to 64-bit remainders, but gcc seems
	 * to generate buggy code.  :/  */
	uint64_t *p = (uint64_t *)&get_block(qf, index /
																			 QF_SLOTS_PER_BLOCK)->slots[(index %
																																QF_SLOTS_PER_BLOCK)
																			 * qf->metadata->bits_per_slot / 8];
	uint64_t t = *p;
	uint64_t mask = BITMASK(qf->metadata->bits_per_slot);
	uint64_t v = value;
	int shift = ((index % QF_SLOTS_PER_BLOCK) * qf->metadata->bits_per_slot) % 8;
	mask <<= shift;
	v <<= shift;
	t &= ~mask;
	t |= v;
	*p = t;
}

#endif

static inline uint64_t run_end(const QF *qf, uint64_t hash_bucket_index);

static inline uint64_t block_offset(const QF *qf, uint64_t blockidx)
{
	/* If we have extended counters and a 16-bit (or larger) offset
		 field, then we can safely ignore the possibility of overflowing
		 that field. */
	if (sizeof(qf->blocks[0].offset) > 1 || 
			get_block(qf, blockidx)->offset < BITMASK(8*sizeof(qf->blocks[0].offset)))
		return get_block(qf, blockidx)->offset;

	return run_end(qf, QF_SLOTS_PER_BLOCK * blockidx - 1) - QF_SLOTS_PER_BLOCK *
		blockidx + 1;
}

static inline uint64_t run_end(const QF *qf, uint64_t hash_bucket_index)
{
	uint64_t bucket_block_index       = hash_bucket_index / QF_SLOTS_PER_BLOCK;
	uint64_t bucket_intrablock_offset = hash_bucket_index % QF_SLOTS_PER_BLOCK;
	uint64_t bucket_blocks_offset = block_offset(qf, bucket_block_index);

	uint64_t bucket_intrablock_rank   = bitrank(get_block(qf, bucket_block_index)->occupieds[0], bucket_intrablock_offset);

	if (bucket_intrablock_rank == 0) {
		if (bucket_blocks_offset <= bucket_intrablock_offset)
			return hash_bucket_index;
		else
			return QF_SLOTS_PER_BLOCK * bucket_block_index + bucket_blocks_offset - 1;
	}

	uint64_t runend_block_index  = bucket_block_index + bucket_blocks_offset / QF_SLOTS_PER_BLOCK;
	uint64_t runend_ignore_bits  = bucket_blocks_offset % QF_SLOTS_PER_BLOCK;
	uint64_t runend_rank         = bucket_intrablock_rank - 1;
	uint64_t runend_block_offset = bitselectv(get_block(qf, runend_block_index)->runends[0] & (~get_block(qf, runend_block_index)->extensions[0]), runend_ignore_bits, runend_rank);
	if (runend_block_offset == QF_SLOTS_PER_BLOCK) {
		if (bucket_blocks_offset == 0 && bucket_intrablock_rank == 0) {
			/* The block begins in empty space, and this bucket is in that region of
			 * empty space */
			return hash_bucket_index;
		} else {
			do {
        // Making sure to ignore the runends of extensions.
        runend_rank -= popcntv(get_block(qf, runend_block_index)->runends[0] & (~get_block(qf, runend_block_index)->extensions[0]), runend_ignore_bits);
        runend_block_index++;
				runend_ignore_bits  = 0;
				runend_block_offset = bitselectv(get_block(qf, runend_block_index)->runends[0] & (~get_block(qf, runend_block_index)->extensions[0]), runend_ignore_bits, runend_rank);
			} while (runend_block_offset == QF_SLOTS_PER_BLOCK);
		}
	}

	uint64_t runend_index = QF_SLOTS_PER_BLOCK * runend_block_index + runend_block_offset;
  // In memento encoding, runends do not have extensions, so don't extend the count. 
  // while (is_extension_or_counter(qf, runend_index + 1)) runend_index++;
	if (runend_index < hash_bucket_index)
		return hash_bucket_index;
	else {
		return runend_index;
	}
}

static inline int offset_lower_bound(const QF *qf, uint64_t slot_index)
{
	//printf("%lu\n", slot_index);
	/*if (slot_index == 613616636) {
		bp1(qf, 0, 0, 0);
		return 0;
	}*/
	const qfblock * b = get_block(qf, slot_index / QF_SLOTS_PER_BLOCK);
	const uint64_t slot_offset = slot_index % QF_SLOTS_PER_BLOCK;
	const uint64_t boffset = b->offset;
	const uint64_t occupieds = b->occupieds[0] & BITMASK(slot_offset+1);
	assert(QF_SLOTS_PER_BLOCK == 64);
	if (boffset <= slot_offset) {
		const uint64_t runends = (b->runends[0] & ~(b->extensions[0]) & BITMASK(slot_offset)) >> boffset;
		//const uint64_t runends = (b->runends[0] & BITMASK(slot_offset)) >> boffset;
		return popcnt(occupieds) - popcnt(runends);
	}
	return boffset - slot_offset + popcnt(occupieds);
}

static inline int is_empty(const QF *qf, uint64_t slot_index)
{
	return offset_lower_bound(qf, slot_index) == 0;
}

static inline int might_be_empty(const QF *qf, uint64_t slot_index)
{
	return !is_occupied(qf, slot_index)
		&& !is_runend_or_counter(qf, slot_index)
		&& !is_extension_or_counter(qf, slot_index);
}

static inline int probably_is_empty(const QF *qf, uint64_t slot_index)
{
	return get_slot(qf, slot_index) == 0
		&& !is_occupied(qf, slot_index)
		&& !is_runend_or_counter(qf, slot_index)
		&& !is_extension_or_counter(qf, slot_index);
}

static inline uint64_t find_first_empty_slot(QF *qf, uint64_t from)
{
	/*if (from == 613572643) {
		return 0;
	}*/
	do {
    // Keepsakes cannot end with extension, so should be good to drop this.
    // while (is_extension_or_counter(qf, from)) from++;
		int t = offset_lower_bound(qf, from);
		//printf("%d\n", t);
    if (t < 0) {
      printf("%d\n", t);
			bp();
			//printf("%d\n", t);
			offset_lower_bound(qf, from);
			return -1;
    }
		assert(t>=0);
		if (t == 0)
			break;
		from = from + t;
	} while(1);
	return from;
}

uint64_t find_first_test(QF *qf, uint64_t from) {
	return find_first_empty_slot(qf, from);
}

static inline uint64_t shift_into_b(const uint64_t a, const uint64_t b, const int bstart, const int bend, const int amount)
{
	const uint64_t a_component = bstart == 0 ? (a >> (64 - amount)) : 0;
	const uint64_t b_shifted_mask = BITMASK(bend - bstart) << bstart;
	const uint64_t b_shifted = ((b_shifted_mask & b) << amount) & b_shifted_mask;
	const uint64_t b_mask = ~b_shifted_mask;
	return a_component | b_shifted | (b & b_mask);
}

#if QF_BITS_PER_SLOT == 8 || QF_BITS_PER_SLOT == 16 || QF_BITS_PER_SLOT == 32 || QF_BITS_PER_SLOT == 64

static inline void shift_remainders(QF *qf, uint64_t start_index, uint64_t empty_index)
{
	uint64_t start_block  = start_index / QF_SLOTS_PER_BLOCK;
	uint64_t start_offset = start_index % QF_SLOTS_PER_BLOCK;
	uint64_t empty_block  = empty_index / QF_SLOTS_PER_BLOCK;
	uint64_t empty_offset = empty_index % QF_SLOTS_PER_BLOCK;

	assert (start_index <= empty_index && empty_index < qf->metadata->xnslots);

	while (start_block < empty_block) {
		memmove(&get_block(qf, empty_block)->slots[1], 
						&get_block(qf, empty_block)->slots[0],
						empty_offset * sizeof(qf->blocks[0].slots[0]));
		get_block(qf, empty_block)->slots[0] = get_block(qf,
																			empty_block-1)->slots[QF_SLOTS_PER_BLOCK-1];
		empty_block--;
		empty_offset = QF_SLOTS_PER_BLOCK-1;
	}

	memmove(&get_block(qf, empty_block)->slots[start_offset+1], 
					&get_block(qf, empty_block)->slots[start_offset],
					(empty_offset - start_offset) * sizeof(qf->blocks[0].slots[0]));
}

#else

#define REMAINDER_WORD(qf, i) ((uint64_t *)&(get_block(qf, (i)/qf->metadata->bits_per_slot)->slots[8 * ((i) % qf->metadata->bits_per_slot)]))

static inline void shift_remainders(QF *qf, const uint64_t start_index, const uint64_t empty_index)
{
	uint64_t last_word = (empty_index + 1) * qf->metadata->bits_per_slot / 64;
	const uint64_t first_word = start_index * qf->metadata->bits_per_slot / 64;
	int bend = ((empty_index + 1) * qf->metadata->bits_per_slot) % 64;
	const int bstart = (start_index * qf->metadata->bits_per_slot) % 64;

	while (last_word != first_word) {
		*REMAINDER_WORD(qf, last_word) = shift_into_b(*REMAINDER_WORD(qf, last_word-1), *REMAINDER_WORD(qf, last_word), 0, bend, qf->metadata->bits_per_slot);
		last_word--;
		bend = 64;
	}
	*REMAINDER_WORD(qf, last_word) = shift_into_b(0, *REMAINDER_WORD(qf, last_word), bstart, bend, qf->metadata->bits_per_slot);
}

#endif

static inline void qf_dump_block(const QF *qf, uint64_t i)
{
	uint64_t j;

	printf("%-192d", get_block(qf, i)->offset);
	printf("\n");

	for (j = 0; j < QF_SLOTS_PER_BLOCK; j++)
		printf("%02lx ", j);
	printf("\n");

	for (j = 0; j < QF_SLOTS_PER_BLOCK; j++)
		printf(" %d ", (get_block(qf, i)->occupieds[j/64] & (1ULL << (j%64))) ? 1 : 0);
	printf("\n");

	for (j = 0; j < QF_SLOTS_PER_BLOCK; j++)
		printf(" %d ", (get_block(qf, i)->runends[j/64] & (1ULL << (j%64))) ? 1 : 0);
	printf("\n");

#if QF_BITS_PER_SLOT == 8 || QF_BITS_PER_SLOT == 16 || QF_BITS_PER_SLOT == 32
	for (j = 0; j < QF_SLOTS_PER_BLOCK; j++)
		printf("%02x ", get_block(qf, i)->slots[j]);
#elif QF_BITS_PER_SLOT == 64
	for (j = 0; j < QF_SLOTS_PER_BLOCK; j++)
		printf("%02lx ", get_block(qf, i)->slots[j]);
#else
	for (j = 0; j < QF_SLOTS_PER_BLOCK * qf->metadata->bits_per_slot / 8; j++)
		printf("%02x ", get_block(qf, i)->slots[j]);
#endif

	printf("\n");

	printf("\n");
}

void qf_dump_metadata(const QF *qf) {
	printf("Slots: %lu Occupied: %lu Elements: %lu Distinct: %lu\n",
				 qf->metadata->nslots,
				 qf->metadata->noccupied_slots,
				 qf->metadata->nelts,
				 qf->metadata->ndistinct_elts);
	printf("Key_bits: %lu Value_bits: %lu Remainder_bits: %lu Bits_per_slot: %lu\n",
				 qf->metadata->key_bits,
				 qf->metadata->value_bits,
				 qf->metadata->key_remainder_bits,
				 qf->metadata->bits_per_slot);
}

void qf_dump(const QF *qf)
{
	uint64_t i;

	printf("%lu %lu %lu\n",
				 qf->metadata->nblocks,
				 qf->metadata->ndistinct_elts,
				 qf->metadata->nelts);

	for (i = 0; i < qf->metadata->nblocks; i++) {
		qf_dump_block(qf, i);
	}

}

static inline void shift_slots(QF *qf, int64_t first, uint64_t last, uint64_t distance)
{
	int64_t i;
	if (distance == 1)
		shift_remainders(qf, first, last+1);
	else
		for (i = last; i >= first; i--)
			set_slot(qf, i + distance, get_slot(qf, i));
}

static inline void shift_runends(QF *qf, int64_t first, uint64_t last, uint64_t distance)
{ // also shifts extensions
	assert(last < qf->metadata->xnslots && distance < 64);
	uint64_t first_word = first / 64;
	uint64_t bstart = first % 64;
	uint64_t last_word = (last + distance + 1) / 64;
	uint64_t bend = (last + distance + 1) % 64;

	if (last_word != first_word) {
		METADATA_WORD(qf, runends, 64*last_word) = shift_into_b(METADATA_WORD(qf, runends, 64*(last_word-1)), METADATA_WORD(qf, runends, 64*last_word), 0, bend, distance);
		METADATA_WORD(qf, extensions, 64*last_word) = shift_into_b(METADATA_WORD(qf, extensions, 64*(last_word-1)), METADATA_WORD(qf, extensions, 64*last_word), 0, bend, distance);
		bend = 64;
		last_word--;
		while (last_word != first_word) {
			METADATA_WORD(qf, runends, 64*last_word) = shift_into_b(METADATA_WORD(qf, runends, 64*(last_word-1)), METADATA_WORD(qf, runends, 64*last_word), 0, bend, distance);
			METADATA_WORD(qf, extensions, 64*last_word) = shift_into_b(METADATA_WORD(qf, extensions, 64*(last_word-1)), METADATA_WORD(qf, extensions, 64*last_word), 0, bend, distance);
			last_word--;
		}
	}
	METADATA_WORD(qf, runends, 64*last_word) = shift_into_b(0, METADATA_WORD(qf, runends, 64*last_word), bstart, bend, distance);
	METADATA_WORD(qf, extensions, 64*last_word) = shift_into_b(0, METADATA_WORD(qf, extensions, 64*last_word), bstart, bend, distance);
}

// if only_item_in_run is true, then we need to unmark the occupied bit because we've cleared out the last item in that bucket
// bucket_index is the hash bucket index of the item to remove
// overwrite_index is the slot index of the item to remove
// old_length is the number of total slots the item was using (the base slot plus any slots used for extensions or counters)
static inline int remove_replace_slots_and_shift_remainders_and_runends_and_offsets(const QF *qf, int only_item_in_run, uint64_t bucket_index,
        uint64_t overwrite_index, uint64_t old_length)
{
	// If this is the last thing in its run, then we may need to set a new runend bit
	int was_runend = is_runend(qf, overwrite_index);
	if (was_runend) {
		if (!only_item_in_run) {
			// This entry is the runend, but it is not the first entry in this run
			// So the preceding entry is to be the new runend
			uint64_t temp = overwrite_index - 1;
			while (is_extension_or_counter(qf, temp)) temp--;
			METADATA_WORD(qf, runends, temp) |= 1ULL << (temp % 64);
		}
	}

	// shift slots back one run at a time
	uint64_t original_bucket = bucket_index;
	uint64_t current_bucket = bucket_index;
	uint64_t current_slot = overwrite_index;
	uint64_t current_distance = old_length;
	int ret_current_distance = current_distance;

	while (current_distance > 0) { // every iteration of this loop deletes one slot from the item and shifts the cluster accordingly
		// start with an occupied-runend pair
		current_bucket = bucket_index;
		current_slot = overwrite_index;
		
		if (!was_runend) while (!is_runend(qf, current_slot)) current_slot++; // step to the end of the run
		while (is_extension_or_counter(qf, current_slot + 1)) current_slot++;
		do {
			current_bucket++;
		} while (current_bucket <= current_slot && !is_occupied(qf, current_bucket)); // step to the next occupied bucket
		// current_slot should now be on the last slot in the run and current_bucket should be on the bucket for the next run

		while (current_bucket <= current_slot) { // until we find the end of the cluster,
			// find the last slot in the run
			current_slot++; // step into the next run
			while (!is_runend(qf, current_slot)) current_slot++; // find the last slot in this run
			while (is_extension_or_counter(qf, current_slot + 1)) current_slot++;

			// find the next bucket
			do {
				current_bucket++;
			} while (current_bucket <= current_slot && !is_occupied(qf, current_bucket));
		}

		// now that we've found the last slot in the cluster, we can shift the whole cluster over by 1
		uint64_t i;
		for (i = overwrite_index; i < current_slot; i++) {
			set_slot(qf, i, get_slot(qf, i + 1));
			if (is_runend_or_counter(qf, i) != is_runend_or_counter(qf, i + 1))
				METADATA_WORD(qf, runends, i) ^= 1ULL << (i % 64);
			if (is_extension_or_counter(qf, i) != is_extension_or_counter(qf, i + 1))
				METADATA_WORD(qf, extensions, i) ^= 1ULL << (i % 64);
		}
		set_slot(qf, i, 0);
		METADATA_WORD(qf, runends, i) &= ~(1ULL << (i % 64));
		METADATA_WORD(qf, extensions, i) &= ~(1ULL << (i % 64));
		
		current_distance--;
	}
	
	// reset the occupied bit of the hash bucket index if the hash is the
	// only item in the run and is removed completely.
	if (only_item_in_run)
		METADATA_WORD(qf, occupieds, bucket_index) &= ~(1ULL << (bucket_index % 64));

	// update the offset bits.
	// find the number of occupied slots in the original_bucket block.
	// Then find the runend slot corresponding to the last run in the
	// original_bucket block.
	// Update the offset of the block to which it belongs.
	uint64_t original_block = original_bucket / QF_SLOTS_PER_BLOCK;
	if (old_length > 0) {	// we only update offsets if we shift/delete anything
		while (1) {
			uint64_t last_occupieds_hash_index = QF_SLOTS_PER_BLOCK * original_block + (QF_SLOTS_PER_BLOCK - 1);
			uint64_t runend_index = run_end(qf, last_occupieds_hash_index);
			// runend spans across the block
			// update the offset of the next block
			if (runend_index / QF_SLOTS_PER_BLOCK == original_block) { // if the run ends in the same block
				if (get_block(qf, original_block + 1)->offset == 0)
					break;
				get_block(qf, original_block + 1)->offset = 0;
			} else { // if the last run spans across the block
				if (get_block(qf, original_block + 1)->offset == (runend_index - last_occupieds_hash_index))
					break;
				get_block(qf, original_block + 1)->offset = (runend_index - last_occupieds_hash_index);
			}
			original_block++;
		}
	}

	int num_slots_freed = old_length;
	//modify_metadata(&qf->runtimedata->pc_noccupied_slots, -num_slots_freed);
	/*qf->metadata->noccupied_slots -= (old_length - total_remainders);*/
	//modify_metadata(&qf->runtimedata->pc_ndistinct_elts, -1);
	//qf->metadata->noccupied_slots -= num_slots_freed;

	return ret_current_distance;
}

/* return the next slot which corresponds to a 
 * different element 
 * */
static inline uint64_t next_slot(QF *qf, uint64_t current) // EDIT: change schema for determining extensions // EDIT2: I don't remember what this means
{
	uint64_t rem = get_slot(qf, current);
	current++;

	while (get_slot(qf, current) == rem && current <= qf->metadata->nslots) {
		current++;
	}
	return current;
}

static inline int get_slot_info(const QF *qf, uint64_t index, uint64_t *ext, int *ext_slots, uint64_t *count, int *count_slots);
//int qf_adapt(QF *qf, uint64_t index, uint64_t hash, uint64_t other_hash, uint8_t flags);
static inline int adapt(QF *qf, uint64_t index, uint64_t hash_bucket_index, uint64_t hash, uint64_t other_hash, uint64_t *ret_hash);


// target_index is the index of the item's target bucket (this is used to update offset)
// insert_index is the index to actually place the item
// value is the data (remainder/extension) to go in the slot
static inline int insert_one_slot(QF *qf, uint64_t target_index, uint64_t insert_index, uint64_t value) {
	/*clock_t start_time = clock();
	if (qf_get_num_occupied_slots(qf) == 97264) {
		printf("%ld\n", clock() - start_time);
	}*/
	uint64_t empty_slot_index = find_first_empty_slot(qf, insert_index); // find the first empty slot // TODO: modify either this or find_first_empty_slot to go to the end of extension
	
	if (empty_slot_index >= qf->metadata->xnslots) {
		return QF_NO_SPACE;
		printf("insert_one_slot hit xnslots\n");
	}
	shift_remainders(qf, insert_index, empty_slot_index); // shift all slots from insert index to the empty slot
	
	set_slot(qf, insert_index, value); // fill the newly made space

	shift_runends(qf, insert_index, empty_slot_index - 1, 1); // shift runend bits from insert index to the empty slot
	
	uint64_t i; // increment offset for all blocks that the shift pushed into
	for (i = target_index / QF_SLOTS_PER_BLOCK + 1; i <= empty_slot_index / QF_SLOTS_PER_BLOCK; i++) {
		if (get_block(qf, i)->offset < BITMASK(8*sizeof(qf->blocks[0].offset))) {
			get_block(qf, i)->offset++;
			// record(qf, "nudge", (value & BITMASK(qf->metadata->bits_per_slot)) | (target_index << qf->metadata->bits_per_slot)
					// | ((value >> qf->metadata->bits_per_slot) << (qf->metadata->quotient_bits + qf->metadata->bits_per_slot)), i);
		}
		/*if (get_block(qf, i)->offset > 65) {
			printf("%d\n", get_block(qf, i)->offset);
		}*/
		assert(get_block(qf, i)->offset != 0);
	}
	
	return 1;
}

FILE *recording = NULL;
void start_recording() {
	if (recording) stop_recording();
	recording = fopen("target/recording.txt", "w");
	fclose(recording);
	recording = fopen("target/recording.txt", "a");
}

void stop_recording() {
	if (!recording) return;
	fclose(recording);
	recording = NULL;
}

int record_break(const QF *qf, char *operation, uint64_t block, uint64_t intra) {
	return 0;
}
int record(const QF *qf, char *operation, uint64_t hash, uint64_t recorded_block) {
	if (!recording) return 0;

	uint64_t orig_hash = hash;
	uint64_t index = (hash >> qf->metadata->bits_per_slot) & BITMASK(qf->metadata->quotient_bits);
	uint64_t block = index / QF_SLOTS_PER_BLOCK;
	uint64_t intra = index % QF_SLOTS_PER_BLOCK;
	uint64_t remainder = hash & BITMASK(qf->metadata->bits_per_slot);

	if (recorded_block == -1) recorded_block = block;
	if (recorded_block != 14260) return 0;
	record_break(qf, operation, block, intra);

	char buffer1[128], buffer2[128];
	bzero(buffer1, 128);
	bzero(buffer2, 128);
	int i = 0, j, k = 0;
	for (j = 0; j < qf->metadata->bits_per_slot; j++) {
		buffer1[i + j + k] = hash & 1 ? '1' : '0';
		hash >>= 1;
	}
	i += j;
	buffer1[i + k++] = '-';
	for (j = 0; j < qf->metadata->quotient_bits; j++) {
		buffer1[i + j + k] = hash & 1 ? '1' : '0';
		hash >>= 1;
	}
	i += j;
	for (i = j + k; i < 64; i += j) {
		buffer1[i + k++] = '-';
		for (j = 0; j < qf->metadata->bits_per_slot; j++) {
			buffer1[i + j + k] = hash & 1 ? '1' : '0';
			hash >>= 1;
		}
	}
	for (j = i + k; j >= 0; j--) {
		buffer2[i + k - j - 1] = buffer1[j];
	}

	fprintf(recording, "%s\t\tblock:%lu\thash:%lu\tbin:%s\n", operation, recorded_block, orig_hash, buffer2);
	fprintf(recording, "\t\tindex:%lu\tfromblock:%lu\tintrablock:%lu\tremainder:%lu\n", index, block, intra, remainder);
	fprintf(recording, "\t\tfill:%lu\toffset:%d\tnext_offset:%d\n", qf->metadata->noccupied_slots, get_block(qf, recorded_block)->offset, get_block(qf, recorded_block + 1)->offset);

	bzero(buffer1, 128);
	bzero(buffer2, 128);
	uint64_t temp = get_block(qf, recorded_block)->occupieds[0];
	for (i = 0; i < 64; i++) {
		buffer1[63 - i] = '0' + (temp & 1);
		temp >>= 1;
	}
	fprintf(recording, "\t\t%s\n", buffer1);
	temp = get_block(qf, recorded_block)->runends[0];
	for (i = 0; i < 64; i++) {
		buffer1[63 - i] = '0' + (temp & 1);
		temp >>= 1;
	}
	fprintf(recording, "\t\t%s\n", buffer1);
	temp = get_block(qf, recorded_block)->extensions[0];
	for (i = 0; i < 64; i++) {
		buffer1[63 - i] = '0' + (temp & 1);
		temp >>= 1;
	}
	fprintf(recording, "\t\t%s\n\n", buffer1);

	return 1;
}

int snapshot(const QF *qf) {
        FILE *fp = fopen("target/snapshot.log", "w");
        if (fp == NULL) return 0;
        char buffer1[128];
        char buffer2[256];
        bzero(buffer1, 128);
        bzero(buffer2, 256);
        int i, j;
        for (i = 0; i * 64 < qf->metadata->xnslots; i++) {
                uint64_t occupied = get_block(qf, i)->occupieds[0];
                for (j = 0; j < 64; j++) {
                        buffer1[63 - j] = '0' + occupied % 2;
                        occupied >>= 1;
                }
                sprintf(buffer2, "%d\t%s\n", i, buffer1);
                //printf("%s", buffer2);
                fputs(buffer2, fp);
                uint64_t runend = get_block(qf, i)->runends[0];
                for (j = 0; j < 64; j++) {
                        buffer1[63 - j] = '0' + runend % 2;
                        runend >>= 1;
                }
                sprintf(buffer2, "%d\t%s\n", get_block(qf, i)->offset, buffer1);
                //printf("%s", buffer2);
                fputs(buffer2, fp);
                uint64_t extension = get_block(qf, i)->extensions[0];
                for (j = 0; j < 64; j++) {
                        buffer1[63 - j] = '0' + extension % 2;
                        extension >>= 1;
                }
                sprintf(buffer2, "\t%s\n", buffer1);
                fputs(buffer2, fp);
        }
        fclose(fp);
        return 1;
}

int tight_inserts = 0;
static inline int insert(QF *qf, uint64_t hash, uint64_t count, uint64_t *ret_index, uint64_t *ret_hash, int *ret_hash_len, uint8_t runtime_lock) // copy of the insert function for modification
// hash is 64 hashed key bits concatenated with 64 value bits
{
  printf("%lx\n", hash);
	/* int ret_distance = 0; */
	uint64_t hash_remainder = hash & BITMASK(qf->metadata->bits_per_slot);
	uint64_t hash_bucket_index = (hash & BITMASK(qf->metadata->quotient_bits + qf->metadata->bits_per_slot)) >> qf->metadata->bits_per_slot;
	uint64_t hash_bucket_block_offset = hash_bucket_index % QF_SLOTS_PER_BLOCK;
  printf("%lx %ld\n", hash_bucket_index, hash_bucket_block_offset);
	/*uint64_t hash_bucket_lock_offset  = hash_bucket_index % NUM_SLOTS_TO_LOCK;*/

	//if (hash_bucket_index / 64 == 14259) record_break(qf, "insert start", hash_bucket_index / 64, hash_bucket_block_offset);
	//if (hash_remainder == 65 && hash_bucket_index / 64 == 6960) bp();
	
	//printf("remainder = %lu   \t index = %lu\n", hash_remainder, hash_bucket_index);

	if (GET_NO_LOCK(runtime_lock) != QF_NO_LOCK) {
		if (!qf_lock(qf, hash_bucket_index, /*small*/ true, runtime_lock))
			return QF_COULDNT_LOCK;
	}

	uint64_t runend_index = run_end(qf, hash_bucket_index);
	
	if (might_be_empty(qf, hash_bucket_index) && runend_index == hash_bucket_index) { /* Empty slot */
		// If slot is empty, insert new element and then call the function again to increment the counter
		set_slot(qf, hash_bucket_index, hash_remainder);
		METADATA_WORD(qf, runends, hash_bucket_index) |= 1ULL << hash_bucket_block_offset;
		METADATA_WORD(qf, occupieds, hash_bucket_index) |= 1ULL << hash_bucket_block_offset;
		
		//modify_metadata(&qf->runtimedata->pc_ndistinct_elts, 1);
		//modify_metadata(&qf->runtimedata->pc_noccupied_slots, 1);
		//modify_metadata(&qf->runtimedata->pc_nelts, 1);
		qf->metadata->ndistinct_elts++;
		qf->metadata->noccupied_slots++;
		qf->metadata->nelts++;

		*ret_hash = hash & BITMASK(qf->metadata->quotient_bits + qf->metadata->bits_per_slot);
		*ret_hash_len = qf->metadata->quotient_bits + qf->metadata->bits_per_slot;
		if (count > 1) {
			insert_and_extend(qf, hash_bucket_index, hash, count - 1, hash, ret_hash, ret_hash, QF_KEY_IS_HASH | QF_NO_LOCK); // ret_hash and ret_hash_len are placeholders
		}
		//printf("inserted in slot %lu - empty slot\n", hash_bucket_index);
	} else { /* Non-empty slot */
		int64_t runstart_index = hash_bucket_index == 0 ? 0 : run_end(qf, hash_bucket_index - 1) + 1;

		if (!is_occupied(qf, hash_bucket_index)) { /* Empty bucket, but its slot is taken. */
			insert_one_slot(qf, hash_bucket_index, runstart_index, hash_remainder);
			
			METADATA_WORD(qf, runends, runstart_index) |= 1ULL << (runstart_index % 64);
			METADATA_WORD(qf, occupieds, hash_bucket_index) |= 1ULL << hash_bucket_block_offset;
			//modify_metadata(&qf->runtimedata->pc_ndistinct_elts, 1);
			//modify_metadata(&qf->runtimedata->pc_noccupied_slots, 1);
			//modify_metadata(&qf->runtimedata->pc_nelts, count);
			qf->metadata->ndistinct_elts++;
			qf->metadata->noccupied_slots++;
			qf->metadata->nelts++;

			*ret_hash = hash & BITMASK(qf->metadata->quotient_bits + qf->metadata->bits_per_slot);
			*ret_hash_len = qf->metadata->quotient_bits + qf->metadata->bits_per_slot;
			if (count > 1) insert_and_extend(qf, hash_bucket_index, hash, count - 1, hash, ret_hash, ret_hash, QF_KEY_IS_HASH | QF_NO_LOCK); // ret_hash is a placeholders
		} else { /* Non-empty bucket */

			/* uint64_t current_remainder, current_count, current_end; */
			uint64_t current_index = runstart_index;
			uint64_t current_remainder;

			uint64_t count_info;
			int count_slots;
			// Find a matching item in the filter, if one exists
			//while (is_extension_or_counter(qf, current_index)) current_index++;
			if (is_extension_or_counter(qf, current_index)) {
				printf("here\n");
			}
			assert(!is_extension_or_counter(qf, current_index));
			int was_runend = 0;
			uint64_t insert_index;
			do {
				current_remainder = get_slot(qf, current_index);
				if (current_remainder > hash_remainder) {
					insert_index = current_index;
					break;
				}
				else if (current_remainder == hash_remainder) {
					if (GET_TRY_ONCE_LOCK(runtime_lock) == QF_TRY_ONCE_LOCK) { // TODO: this is just hijacking the TRY_ONCE_LOCK flag to represent a FORCE_INSERT flag
						insert_index = current_index;
						break;
					}
					get_slot_info(qf, current_index, ret_hash, ret_hash_len, &count_info, &count_slots);

					if (*ret_hash == ((hash >> (qf->metadata->quotient_bits + qf->metadata->bits_per_slot)) & BITMASK(*ret_hash_len * qf->metadata->bits_per_slot))) {
						*ret_index = current_index;
						*ret_hash = (*ret_hash << (qf->metadata->quotient_bits + qf->metadata->bits_per_slot)) | (hash & BITMASK(qf->metadata->quotient_bits + qf->metadata->bits_per_slot));
						*ret_hash_len = (*ret_hash_len * qf->metadata->bits_per_slot) + qf->metadata->quotient_bits + qf->metadata->bits_per_slot;

						if (GET_NO_LOCK(runtime_lock) != QF_NO_LOCK) {
							qf_unlock(qf, hash_bucket_index, /*small*/ true);
						}
						return 0;
					}

					if (is_runend(qf, current_index)) {
						was_runend = 1;
						insert_index = current_index + 1 + *ret_hash_len + count_slots;
						break;
					}
					current_index += count_slots + *ret_hash_len + 1;
				}
				else if (is_runend(qf, current_index)) {
					was_runend = 1;
					insert_index = current_index + 1;
					while (is_extension_or_counter(qf, insert_index)) insert_index++;
					break;
				}
				else {
					current_index++;
					while (is_extension_or_counter(qf, current_index)) current_index++;
				}
			} while (current_index < qf->metadata->xnslots);
			if (current_index >= qf->metadata->xnslots) {
				printf("error: program reached end of filter without finding runend\n");
				if (GET_NO_LOCK(runtime_lock) != QF_NO_LOCK) {
					qf_unlock(qf, hash_bucket_index, /*small*/ true);
				}
				return QF_NO_SPACE;
			}

			insert_one_slot(qf, hash_bucket_index, insert_index, hash_remainder);
			if (was_runend) {
				METADATA_WORD(qf, runends, insert_index) |= (1ULL << (insert_index % QF_SLOTS_PER_BLOCK));
				METADATA_WORD(qf, runends, current_index) ^= (1ULL << (current_index % QF_SLOTS_PER_BLOCK));
			}
			
			//modify_metadata(&qf->runtimedata->pc_ndistinct_elts, 1);
			//modify_metadata(&qf->runtimedata->pc_noccupied_slots, 1);
			//modify_metadata(&qf->runtimedata->pc_nelts, count);
			qf->metadata->ndistinct_elts++;
			qf->metadata->noccupied_slots++;
			qf->metadata->nelts++;

			*ret_hash = hash & BITMASK(qf->metadata->quotient_bits + qf->metadata->bits_per_slot);
			*ret_hash_len = qf->metadata->quotient_bits + qf->metadata->bits_per_slot;
			if (count > 1) *ret_hash_len = insert_and_extend(qf, insert_index, hash, count - 1, hash, ret_hash, ret_hash, QF_KEY_IS_HASH | QF_NO_LOCK); // ret_hash and ret_hash_len are placeholders
		}
	}

	if (GET_NO_LOCK(runtime_lock) != QF_NO_LOCK) {
		qf_unlock(qf, hash_bucket_index, /*small*/ true);
	}

	return 1;
}

static inline int insert_using_ll_table(QF *qf, qf_insert_result *result, uint64_t count, uint8_t runtime_lock) // copy of the insert function for modification
// hash is 64 hashed key bits concatenated with 64 value bits
{
	/* int ret_distance = 0; */
	uint64_t hash_remainder = result->hash & BITMASK(qf->metadata->bits_per_slot);
	uint64_t hash_bucket_index = (result->hash & BITMASK(qf->metadata->quotient_bits + qf->metadata->bits_per_slot)) >> qf->metadata->bits_per_slot;
	uint64_t hash_bucket_block_offset = hash_bucket_index % QF_SLOTS_PER_BLOCK;
	/*uint64_t hash_bucket_lock_offset  = hash_bucket_index % NUM_SLOTS_TO_LOCK;*/

	//if (hash_bucket_index / 64 == 14259) record_break(qf, "insert start", hash_bucket_index / 64, hash_bucket_block_offset);
	
	//printf("remainder = %lu   \t index = %lu\n", hash_remainder, hash_bucket_index);

	if (GET_NO_LOCK(runtime_lock) != QF_NO_LOCK) {
		if (!qf_lock(qf, hash_bucket_index, true, runtime_lock))
			return QF_COULDNT_LOCK;
	}

	uint64_t runend_index = run_end(qf, hash_bucket_index);
	
	int ret_code = 0;
	if (might_be_empty(qf, hash_bucket_index) && runend_index == hash_bucket_index) { /* Empty slot */
		// If slot is empty, insert new element and then call the function again to increment the counter
		set_slot(qf, hash_bucket_index, hash_remainder);
		METADATA_WORD(qf, runends, hash_bucket_index) |= 1ULL << hash_bucket_block_offset;
		METADATA_WORD(qf, occupieds, hash_bucket_index) |= 1ULL << hash_bucket_block_offset;
		
#if METADATA_INC_MODE == 1
		qf->metadata->ndistinct_elts++;
		qf->metadata->noccupied_slots++;
		qf->metadata->nelts++;
#elif METADATA_INC_MODE == 2
		modify_metadata(&qf->runtimedata->pc_ndistinct_elts, 1);
		modify_metadata(&qf->runtimedata->pc_noccupied_slots, 1);
		modify_metadata(&qf->runtimedata->pc_nelts, 1);
#endif

		if (count > 1) {
			insert_and_extend(qf, hash_bucket_index, result->hash, count - 1, result->hash, result->hash, result->hash, QF_KEY_IS_HASH | QF_NO_LOCK); // ret_hash and ret_hash_len are placeholders
		}
		//printf("inserted in slot %lu - empty slot\n", hash_bucket_index);
	} else { /* Non-empty slot */
		int64_t runstart_index = hash_bucket_index == 0 ? 0 : run_end(qf, hash_bucket_index - 1) + 1;

		if (!is_occupied(qf, hash_bucket_index)) { /* Empty bucket, but its slot is taken. */
			insert_one_slot(qf, hash_bucket_index, runstart_index, hash_remainder);
			
			METADATA_WORD(qf, runends, runstart_index) |= 1ULL << (runstart_index % 64);
			METADATA_WORD(qf, occupieds, hash_bucket_index) |= 1ULL << hash_bucket_block_offset;

#if METADATA_INC_MODE == 1
			qf->metadata->ndistinct_elts++;
			qf->metadata->noccupied_slots++;
			qf->metadata->nelts++;
#elif METADATA_INC_MODE == 2
			modify_metadata(&qf->runtimedata->pc_ndistinct_elts, 1);
			modify_metadata(&qf->runtimedata->pc_noccupied_slots, 1);
			modify_metadata(&qf->runtimedata->pc_nelts, count);
#endif

			if (count > 1) insert_and_extend(qf, hash_bucket_index, result->hash, count - 1, result->hash, result->hash, result->hash, QF_KEY_IS_HASH | QF_NO_LOCK); // ret_hash is a placeholders
		} else { /* Non-empty bucket */

			/* uint64_t current_remainder, current_count, current_end; */
			uint64_t current_index = runstart_index;
			uint64_t current_remainder;

			uint64_t count_info;
			int count_slots;
			// Find a matching item in the filter, if one exists
			//while (is_extension_or_counter(qf, current_index)) current_index++;
			assert(!is_extension_or_counter(qf, current_index));
			int was_runend = 0;
			uint64_t insert_index;
			do {
				current_remainder = get_slot(qf, current_index);
				if (current_remainder >= hash_remainder) {
					if (current_remainder == hash_remainder) result->minirun_existed = 1;
					insert_index = current_index;
					break;
				}
				else if (is_runend(qf, current_index)) {
					was_runend = 1;
					insert_index = current_index + 1;
					while (is_extension_or_counter(qf, insert_index)) insert_index++;
					break;
				}
				else {
					current_index++;
					while (is_extension_or_counter(qf, current_index)) current_index++;
				}
			} while (current_index < qf->metadata->xnslots);
			if (current_index >= qf->metadata->xnslots) {
				if (GET_NO_LOCK(runtime_lock) != QF_NO_LOCK) {
					qf_unlock(qf, hash_bucket_index, /*small*/ true);
				}
				printf("error: program reached end of filter without finding runend\n");
				return QF_NO_SPACE;
			}

			insert_one_slot(qf, hash_bucket_index, insert_index, hash_remainder);
			if (was_runend) {
				METADATA_WORD(qf, runends, insert_index) |= (1ULL << (insert_index % QF_SLOTS_PER_BLOCK));
				METADATA_WORD(qf, runends, current_index) ^= (1ULL << (current_index % QF_SLOTS_PER_BLOCK));
			}
			
#if METADATA_INC_MODE == 1
			qf->metadata->ndistinct_elts++;
			qf->metadata->noccupied_slots++;
			qf->metadata->nelts += count;
#elif METADATA_INC_MODE == 2
			modify_metadata(&qf->runtimedata->pc_ndistinct_elts, 1);
			modify_metadata(&qf->runtimedata->pc_noccupied_slots, 1);
			modify_metadata(&qf->runtimedata->pc_nelts, count);
#endif

			if (count > 1) insert_and_extend(qf, insert_index, result->hash, count - 1, result->hash, result->hash, result->hash, QF_KEY_IS_HASH | QF_NO_LOCK); // ret_hash and ret_hash_len are placeholders
		}
	}

	if (GET_NO_LOCK(runtime_lock) != QF_NO_LOCK) {
		qf_unlock(qf, hash_bucket_index, /*small*/ true);
	}

	return 0;
}

int qf_insert_using_ll_table(QF *qf, uint64_t key, uint64_t count, qf_insert_result *result, uint8_t flags)
{
	// We fill up the CQF up to 95% load factor.
	// This is a very conservative check.
#if METADATA_INC_MODE == 2
	if (qf_get_num_occupied_slots(qf) >= qf->metadata->nslots * 0.95) {
#else
	if (qf->metadata->noccupied_slots >= qf->metadata->nslots * 0.95) {
#endif
		if (qf->runtimedata->auto_resize) {
			/*fprintf(stdout, "Resizing the CQF.\n");*/
			if (qf->runtimedata->container_resize(qf, qf->metadata->nslots * 2) < 0)
			{
				fprintf(stderr, "Resizing failed.\n");
				return QF_NO_SPACE;
			}
		} else {
			return QF_NO_SPACE;
		}
	}
	if (count == 0)
		return 0;

	result->hash = key;
	if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
		if (qf->metadata->hash_mode == QF_HASH_DEFAULT)
			result->hash = MurmurHash64A(((void *)&key), sizeof(key), qf->metadata->seed);
		else if (qf->metadata->hash_mode == QF_HASH_INVERTIBLE)
			result->hash = hash_64(key, -1ULL);
	}
	//uint64_t hash = ((key << qf->metadata->value_bits) | (value & BITMASK(qf->metadata->value_bits)));// % qf->metadata->range;
	
	result->minirun_existed = 0;
	result->minirun_id = result->hash & BITMASK(qf->metadata->quotient_bits + qf->metadata->bits_per_slot);
	return insert_using_ll_table(qf, result, count, flags);
}

int qf_query_using_ll_table(const QF *qf, uint64_t key, uint64_t *ret_hash, uint8_t flags) {
	// Convert key to hash
	if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
		if (qf->metadata->hash_mode == QF_HASH_DEFAULT)
			*ret_hash = MurmurHash64A(((void *)&key), sizeof(key), qf->metadata->seed);
		else if (qf->metadata->hash_mode == QF_HASH_INVERTIBLE)
			*ret_hash = hash_64(key, -1ULL);
		else
			*ret_hash = key;
	}
	else {
		*ret_hash = key;
	}
	//uint64_t hash = (key << qf->metadata->value_bits) | (value & BITMASK(qf->metadata->value_bits));
	uint64_t hash_remainder   = *ret_hash & BITMASK(qf->metadata->bits_per_slot);
	uint64_t hash_bucket_index = (*ret_hash >> qf->metadata->bits_per_slot) & BITMASK(qf->metadata->quotient_bits);

	// If no one wants this slot, we can already say for certain the item is not in the filter
	if (!is_occupied(qf, hash_bucket_index))
		return -1;

	// Otherwise, find the start of the run (all the items that want that slot) and parse for the remainder we're looking for
	uint64_t runstart_index = hash_bucket_index == 0 ? 0 : run_end(qf, hash_bucket_index - 1) + 1;
	if (runstart_index < hash_bucket_index)
		runstart_index = hash_bucket_index;

	uint64_t current_index = runstart_index;
	int minirun_rank = 0;
	do {
		if (get_slot(qf, current_index) == hash_remainder) { // if first slot matches, check remaining extensions
			uint64_t ext, count;
			int ext_len, count_len;
			get_slot_info(qf, current_index, &ext, &ext_len, &count, &count_len);
			if ((((*ret_hash) >> (qf->metadata->quotient_bits + qf->metadata->bits_per_slot)) & BITMASK(qf->metadata->bits_per_slot * ext_len)) == ext) { // if extensions match, return the count
				return minirun_rank;
			}
			if (is_runend(qf, current_index++)) break; // if extensions don't match, stop if end of run, skip to next item otherwise
			current_index += ext_len + count_len;
			minirun_rank++;
		}
		else { // if first slot doesn't match, stop if end of run, skip to next item otherwise
			if (is_runend(qf, current_index++)) break;
			while (is_extension_or_counter(qf, current_index)) current_index++;
		}
	} while (current_index < qf->metadata->xnslots); // stop if reached the end of all items (should never actually reach this point because should stop at the runend)

	return -1;
}

int qf_get_count_using_ll_table(const QF *qf, uint64_t key, uint64_t *ret_hash, uint8_t *ret_minirun_rank, uint8_t flags) {
	// Convert key to hash
	if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
		if (qf->metadata->hash_mode == QF_HASH_DEFAULT)
			*ret_hash = MurmurHash64A(((void *)&key), sizeof(key), qf->metadata->seed);
		else if (qf->metadata->hash_mode == QF_HASH_INVERTIBLE)
			*ret_hash = hash_64(key, -1ULL);
		else
			*ret_hash = key;
	}
	else {
		*ret_hash = key;
	}
	//uint64_t hash = (key << qf->metadata->value_bits) | (value & BITMASK(qf->metadata->value_bits));
	uint64_t hash_remainder   = *ret_hash & BITMASK(qf->metadata->bits_per_slot);
	uint64_t hash_bucket_index = (*ret_hash >> qf->metadata->bits_per_slot) & BITMASK(qf->metadata->quotient_bits);

	// If no one wants this slot, we can already say for certain the item is not in the filter
	if (!is_occupied(qf, hash_bucket_index))
		return 0;

	// Otherwise, find the start of the run (all the items that want that slot) and parse for the remainder we're looking for
	uint64_t runstart_index = hash_bucket_index == 0 ? 0 : run_end(qf, hash_bucket_index - 1) + 1;
	if (runstart_index < hash_bucket_index)
		runstart_index = hash_bucket_index;

	uint64_t current_index = runstart_index;
	*ret_minirun_rank = 0;
	do {
		if (get_slot(qf, current_index) == hash_remainder) { // if first slot matches, check remaining extensions
			uint64_t ext, count;
			int ext_len, count_len;
			get_slot_info(qf, current_index, &ext, &ext_len, &count, &count_len);
			if (((*ret_hash >> (qf->metadata->quotient_bits + qf->metadata->bits_per_slot)) & BITMASK(qf->metadata->bits_per_slot * ext_len)) == ext) { // if extensions match, return the count
				return count;
			}
			*ret_minirun_rank++;
			if (is_runend(qf, current_index++)) break; // if extensions don't match, stop if end of run, skip to next item otherwise
			current_index += ext_len + count_len;
		}
		else { // if first slot doesn't match, stop if end of run, skip to next item otherwise
			if (is_runend(qf, current_index++)) break;
			while (is_extension_or_counter(qf, current_index)) current_index++;
		}
	} while (current_index < qf->metadata->xnslots); // stop if reached the end of all items (should never actually reach this point because should stop at the runend)

	return 0;
}

int insert_and_extend(QF *qf, uint64_t index, uint64_t key, uint64_t count, uint64_t other_key, uint64_t *ret_hash, uint64_t *ret_other_hash, uint8_t flags)
{
	if (GET_NO_LOCK(flags) != QF_NO_LOCK) {
		if (!qf_lock(qf, index, /*small*/ false, flags))
			return QF_COULDNT_LOCK;
	}

	if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
		if (qf->metadata->hash_mode == QF_HASH_DEFAULT) {
			key = MurmurHash64A(((void *)&key), sizeof(key), qf->metadata->seed);
			other_key = MurmurHash64A(((void *)&other_key), sizeof(other_key), qf->metadata->seed);
		}
		else if (qf->metadata->hash_mode == QF_HASH_INVERTIBLE) {
			key = hash_64(key, -1ULL);
			other_key = hash_64(other_key, -1ULL);
		}
	}
	//uint64_t hash = (key << qf->metadata->value_bits) | (value & BITMASK(qf->metadata->value_bits));
	//uint64_t other_hash = (other_key << qf->metadata->value_bits) | (other_value & BITMASK(qf->metadata->value_bits));
	uint64_t hash = key;
	uint64_t other_hash = other_key;

	if ((hash & BITMASK(qf->metadata->quotient_bits + qf->metadata->bits_per_slot)) != (other_hash & BITMASK(qf->metadata->quotient_bits + qf->metadata->bits_per_slot))) {
		printf("error: original hash is %lu and new hash is %lu\n", other_hash, hash);
	}
	assert((hash & BITMASK(qf->metadata->quotient_bits + qf->metadata->bits_per_slot)) == (other_hash & BITMASK(qf->metadata->quotient_bits + qf->metadata->bits_per_slot)));

	int extended_len = 0;

	if (hash == other_hash) { // same item, increment counter // TODO: check that offset bits are properly set
		uint64_t ext, counter;
		int ext_len, counter_len;
		get_slot_info(qf, index, &ext, &ext_len, &counter, &counter_len);
		uint64_t new_count = counter + count;
		int i;
		for (i = 0; i < counter_len; i++) {
			set_slot(qf, index + 1 + ext + i, new_count & BITMASK(qf->metadata->bits_per_slot));
			new_count >>= qf->metadata->bits_per_slot;
		}
		for (; new_count > 0; i++) {
			insert_one_slot(qf, (hash >> qf->metadata->bits_per_slot) & BITMASK(qf->metadata->quotient_bits), index + 1 + ext_len + i, new_count & BITMASK(qf->metadata->bits_per_slot));
			METADATA_WORD(qf, extensions, index + 1 + ext_len + i) |= 1ULL << ((index + 1 + ext_len + i) % QF_SLOTS_PER_BLOCK);
			METADATA_WORD(qf, runends, index + 1 + ext_len + i) |= 1ULL << ((index + 1 + ext_len + i) % QF_SLOTS_PER_BLOCK);
			//modify_metadata(&qf->runtimedata->pc_noccupied_slots, 1);
			qf->metadata->noccupied_slots++;
			new_count >>= qf->metadata->bits_per_slot;
		}
		//modify_metadata(&qf->runtimedata->pc_nelts, count);
		qf->metadata->nelts += count;
	}
	else { // different items, insert second item and extend both

		//uint64_t before = qf_get_num_occupied_slots(qf);
		uint64_t hash_bucket_index = (hash % qf->metadata->range) >> qf->metadata->bits_per_slot;

		extended_len = adapt(qf, index, hash_bucket_index, other_hash, hash, ret_other_hash);
		insert_one_slot(qf, (hash >> qf->metadata->bits_per_slot) & BITMASK(qf->metadata->quotient_bits), index, hash & BITMASK(qf->metadata->bits_per_slot));
		adapt(qf, index, hash_bucket_index, hash, other_hash, ret_hash);

		//modify_metadata(&qf->runtimedata->pc_ndistinct_elts, 1);
		//modify_metadata(&qf->runtimedata->pc_noccupied_slots, 1);
		//modify_metadata(&qf->runtimedata->pc_nelts, 1);
		qf->metadata->ndistinct_elts++;
		qf->metadata->noccupied_slots++;
		qf->metadata->nelts++;
		if (count > 1) insert_and_extend(qf, index, key, count - 1, key, ret_hash, ret_other_hash, flags | QF_NO_LOCK); // ret_hash and ret_hash_len are placeholders
		record(qf, "extend", hash, -1);
	}

	if (GET_NO_LOCK(flags) != QF_NO_LOCK) {
		qf_unlock(qf, index, /*small*/ false);
	}

	return extended_len;
}

inline static int _remove(QF *qf, uint64_t hash, uint64_t *ret_hash, int *ret_hash_len,  uint8_t runtime_lock)
{
	// hash_remainder is last 7 bits of hash, hash_bucket_index is quotient
	int ret_numfreedslots = 0;
	uint64_t hash_remainder           = hash & BITMASK(qf->metadata->bits_per_slot);
	uint64_t hash_bucket_index        = (hash >> qf->metadata->bits_per_slot) & BITMASK(qf->metadata->quotient_bits);
	//uint64_t current_remainder, current_count, current_end;

	// Lock mutex
	if (GET_NO_LOCK(runtime_lock) != QF_NO_LOCK) {
		if (!qf_lock(qf, hash_bucket_index, /*small*/ false, runtime_lock))
			return -2;
	}

	// If slot is empty, don't bother
	if (!is_occupied(qf, hash_bucket_index))
		return 0;

	uint64_t original_runstart_index = hash_bucket_index == 0 ? 0 : run_end(qf, hash_bucket_index - 1) + 1;
	uint64_t current_index = original_runstart_index;
	int only_item_in_run = 0;

	uint64_t count_info;
	int count_slots;
	// Find a matching item in the filter, if one exists
	while (is_extension_or_counter(qf, current_index)) current_index++;
	do {
		if (get_slot(qf, current_index) == hash_remainder) {
			get_slot_info(qf, current_index, ret_hash, ret_hash_len, &count_info, &count_slots);

			if (*ret_hash == ((hash >> (qf->metadata->quotient_bits + qf->metadata->bits_per_slot)) & BITMASK(*ret_hash_len * qf->metadata->bits_per_slot))) {
				if (current_index == original_runstart_index && is_runend(qf, current_index)) only_item_in_run = 1;
				int ret_freed_slots = remove_replace_slots_and_shift_remainders_and_runends_and_offsets(qf, only_item_in_run, hash_bucket_index, current_index, count_slots + *ret_hash_len + 1);
				
				qf->metadata->noccupied_slots -= ret_freed_slots;
				qf->metadata->ndistinct_elts--;
				qf->metadata->nelts -= count_info;

				if (GET_NO_LOCK(runtime_lock) != QF_NO_LOCK) {
					qf_unlock(qf, hash_bucket_index, /*small*/ false);
				}
				return ret_freed_slots;
			}

			if (is_runend(qf, current_index)) break;
			current_index += count_slots + *ret_hash_len + 1;
		}
		else if (is_runend(qf, current_index)) break;
		else {
			while (is_extension_or_counter(qf, ++current_index)) current_index++;
		}
	} while (current_index < qf->metadata->xnslots);

	if (GET_NO_LOCK(runtime_lock) != QF_NO_LOCK) {
		qf_unlock(qf, hash_bucket_index, /*small*/ false);
	}

	return 0;
}

/***********************************************************************
 * Code that uses the above to implement key-value-counter operations. *
 ***********************************************************************/

uint64_t qf_init(QF *qf, uint64_t nslots, uint64_t key_bits, uint64_t value_bits,
								 enum qf_hashmode hash, uint32_t seed, void* buffer, uint64_t
								 buffer_len)
{
  // key_bits does not include value (memento bits).
	uint64_t num_slots, xnslots, nblocks, qbits;
	uint64_t key_remainder_bits, bits_per_slot;
	uint64_t size;
	uint64_t total_num_bytes;

  // Scale up nslots to nearest power of 2 (Memento does this).
  //assert(popcnt(nslots) == 1); /* nslots must be a power of 2 */
	qbits = num_slots = nslots;
	xnslots = nslots + 10*sqrt((double)nslots);
	nblocks = (xnslots + QF_SLOTS_PER_BLOCK - 1) / QF_SLOTS_PER_BLOCK;
	key_remainder_bits = key_bits;
	while (nslots > 1 && key_remainder_bits > 0) {
		key_remainder_bits--;
		nslots >>= 1;
	}
  key_remainder_bits -= (popcnt(num_slots) > 1);
	assert(key_remainder_bits >= 2);

	bits_per_slot = key_remainder_bits + value_bits;
	assert (QF_BITS_PER_SLOT == 0 || QF_BITS_PER_SLOT == qf->metadata->bits_per_slot);
	assert(bits_per_slot > 1);
#if QF_BITS_PER_SLOT == 8 || QF_BITS_PER_SLOT == 16 || QF_BITS_PER_SLOT == 32 || QF_BITS_PER_SLOT == 64
	size = nblocks * sizeof(qfblock);
#else
	size = nblocks * (sizeof(qfblock) + QF_SLOTS_PER_BLOCK * bits_per_slot / 8);
#endif

	total_num_bytes = sizeof(qfmetadata) + size;
	if (buffer == NULL || total_num_bytes > buffer_len)
		return total_num_bytes;

	// memset(buffer, 0, total_num_bytes);
	qf->metadata = (qfmetadata *)(buffer);
	qf->blocks = (qfblock *)(qf->metadata + 1);

	qf->metadata->magic_endian_number = MAGIC_NUMBER;
	qf->metadata->reserved = 0;
	qf->metadata->hash_mode = hash;
	qf->metadata->total_size_in_bytes = size;
	qf->metadata->seed = seed;
	qf->metadata->nslots = num_slots;
	qf->metadata->xnslots = xnslots;
	qf->metadata->key_bits = key_bits;
	qf->metadata->value_bits = value_bits;
	qf->metadata->key_remainder_bits = key_remainder_bits;
	qf->metadata->bits_per_slot = bits_per_slot;
	qf->metadata->quotient_bits = key_bits - key_remainder_bits;
	#if 0
	while (qbits > 1) {
		qbits >>= 1;
		qf->metadata->quotient_bits++;
	}
	#endif
	qf->metadata->quotient_remainder_bits = qf->metadata->quotient_bits + qf->metadata->bits_per_slot;

	qf->metadata->range = qf->metadata->nslots;
	qf->metadata->range <<= qf->metadata->key_remainder_bits;
	qf->metadata->nblocks = (qf->metadata->xnslots + QF_SLOTS_PER_BLOCK - 1) /
		QF_SLOTS_PER_BLOCK;
	qf->metadata->nelts = 0;
	qf->metadata->ndistinct_elts = 0;
	qf->metadata->noccupied_slots = 0;

	qf->runtimedata->num_locks = (qf->metadata->xnslots/NUM_SLOTS_TO_LOCK)+2;

	pc_init(&qf->runtimedata->pc_nelts, (int64_t*)&qf->metadata->nelts, 8, 100);
	pc_init(&qf->runtimedata->pc_ndistinct_elts, (int64_t*)&qf->metadata->ndistinct_elts, 8, 100);
	pc_init(&qf->runtimedata->pc_noccupied_slots, (int64_t*)&qf->metadata->noccupied_slots, 8, 100);
	/* initialize container resize */
	qf->runtimedata->auto_resize = 0;
	qf->runtimedata->container_resize = qf_resize_malloc;
	/* initialize all the locks to 0 */
	qf->runtimedata->metadata_lock = 0;
	qf->runtimedata->locks = (volatile int *)calloc(qf->runtimedata->num_locks,
																					sizeof(volatile int));
	if (qf->runtimedata->locks == NULL) {
		perror("Couldn't allocate memory for runtime locks.");
		exit(EXIT_FAILURE);
	}
#ifdef LOG_WAIT_TIME
	qf->runtimedata->wait_times = (wait_time_data*
																 )calloc(qf->runtimedata->num_locks+1,
																				 sizeof(wait_time_data));
	if (qf->runtimedata->wait_times == NULL) {
		perror("Couldn't allocate memory for runtime wait_times.");
		exit(EXIT_FAILURE);
	}
#endif

	return total_num_bytes;
}

uint64_t qf_use(QF* qf, void* buffer, uint64_t buffer_len)
{
	qf->metadata = (qfmetadata *)(buffer);
	if (qf->metadata->total_size_in_bytes + sizeof(qfmetadata) > buffer_len) {
		return qf->metadata->total_size_in_bytes + sizeof(qfmetadata);
	}
	qf->blocks = (qfblock *)(qf->metadata + 1);

	qf->runtimedata = (qfruntime *)calloc(sizeof(qfruntime), 1);
	if (qf->runtimedata == NULL) {
		perror("Couldn't allocate memory for runtime data.");
		exit(EXIT_FAILURE);
	}
	/* initialize all the locks to 0 */
	qf->runtimedata->metadata_lock = 0;
	qf->runtimedata->locks = (volatile int *)calloc(qf->runtimedata->num_locks,
																					sizeof(volatile int));
	if (qf->runtimedata->locks == NULL) {
		perror("Couldn't allocate memory for runtime locks.");
		exit(EXIT_FAILURE);
	}
#ifdef LOG_WAIT_TIME
	qf->runtimedata->wait_times = (wait_time_data*
																 )calloc(qf->runtimedata->num_locks+1,
																				 sizeof(wait_time_data));
	if (qf->runtimedata->wait_times == NULL) {
		perror("Couldn't allocate memory for runtime wait_times.");
		exit(EXIT_FAILURE);
	}
#endif

	return sizeof(qfmetadata) + qf->metadata->total_size_in_bytes;
}

void *qf_destroy(QF *qf)
{
	assert(qf->runtimedata != NULL);
	if (qf->runtimedata->locks != NULL)
		free((void*)qf->runtimedata->locks);
	if (qf->runtimedata->wait_times != NULL)
		free(qf->runtimedata->wait_times);
	if (qf->runtimedata->f_info.filepath != NULL)
		free(qf->runtimedata->f_info.filepath);
	free(qf->runtimedata);

	return (void*)qf->metadata;
}

bool qf_malloc(QF *qf, uint64_t nslots, uint64_t key_bits, uint64_t
							 value_bits, enum qf_hashmode hash, uint32_t seed)
{
	uint64_t total_num_bytes = qf_init(qf, nslots, key_bits, value_bits,
																		 hash, seed, NULL, 0);

	void *buffer = malloc(total_num_bytes);
  memset(buffer, 0, total_num_bytes);
	//printf("allocated %lu for total_num_bytes\n", total_num_bytes);
	if (buffer == NULL) {
		perror("Couldn't allocate memory for the CQF.");
		exit(EXIT_FAILURE);
	}

	qf->runtimedata = (qfruntime *)calloc(sizeof(qfruntime), 1);
	//printf("allocated %lu for runtimedata\n", sizeof(qfruntime));
	if (qf->runtimedata == NULL) {
		perror("Couldn't allocate memory for runtime data.");
		exit(EXIT_FAILURE);
	}

	uint64_t init_size = qf_init(qf, nslots, key_bits, value_bits, hash, seed,
															 buffer, total_num_bytes);

	if (init_size == total_num_bytes)
		return true;
	else
		return false;
}

bool qf_free(QF *qf)
{
	assert(qf->metadata != NULL);
	void *buffer = qf_destroy(qf);
	if (buffer != NULL) {
		free(buffer);
		return true;
	}

	return false;
}

void qf_copy(QF *dest, const QF *src)
{
	DEBUG_CQF("%s\n","Source CQF");
	DEBUG_DUMP(src);
	memcpy(dest->runtimedata, src->runtimedata, sizeof(qfruntime));
	memcpy(dest->metadata, src->metadata, sizeof(qfmetadata));
	memcpy(dest->blocks, src->blocks, src->metadata->total_size_in_bytes);
	DEBUG_CQF("%s\n","Destination CQF after copy.");
	DEBUG_DUMP(dest);
}

void qf_reset(QF *qf)
{
	qf->metadata->nelts = 0;
	qf->metadata->ndistinct_elts = 0;
	qf->metadata->noccupied_slots = 0;

#ifdef LOG_WAIT_TIME
	memset(qf->wait_times, 0,
				 (qf->runtimedata->num_locks+1)*sizeof(wait_time_data));
#endif
#if QF_BITS_PER_SLOT == 8 || QF_BITS_PER_SLOT == 16 || QF_BITS_PER_SLOT == 32 || QF_BITS_PER_SLOT == 64
	memset(qf->blocks, 0, qf->metadata->nblocks* sizeof(qfblock));
#else
	memset(qf->blocks, 0, qf->metadata->nblocks*(sizeof(qfblock) + QF_SLOTS_PER_BLOCK *
																		 qf->metadata->bits_per_slot / 8));
#endif
}

/*int64_t qf_resize_malloc(QF *qf, uint64_t nslots)
{
	printf("malloc\n");
	QF new_qf;
	if (!qf_malloc(&new_qf, nslots, qf->metadata->key_bits,
								 qf->metadata->value_bits, qf->metadata->hash_mode,
								 qf->metadata->seed))
		return -1;
	if (qf->runtimedata->auto_resize)
		qf_set_auto_resize(&new_qf, true);

	// copy keys from qf into new_qf
	QFi qfi;
	qf_iterator_from_position(qf, &qfi, 0);
	int64_t ret_numkeys = 0;
	do {
		uint64_t key, value, count;
		//qfi_get_hash(&qfi, &key, &count);
		qfi_next(&qfi);
		int ret = qf_insert(&new_qf, key, value, count, QF_NO_LOCK | QF_KEY_IS_HASH);
		if (ret < 0) {
			fprintf(stderr, "Failed to insert key: %ld into the new CQF.\n", key);
			return ret;
		}
		ret_numkeys++;
	} while(!qfi_end(&qfi));

	qf_free(qf);
	memcpy(qf, &new_qf, sizeof(QF));

	return ret_numkeys;
}*/

uint64_t qf_resize(QF* qf, uint64_t nslots, void* buffer, uint64_t buffer_len)
{
	QF new_qf;
	new_qf.runtimedata = (qfruntime *)calloc(sizeof(qfruntime), 1);
	if (new_qf.runtimedata == NULL) {
		perror("Couldn't allocate memory for runtime data.\n");
		exit(EXIT_FAILURE);
	}

	uint64_t init_size = qf_init(&new_qf, nslots, qf->metadata->key_bits,
															 qf->metadata->value_bits,
															 qf->metadata->hash_mode, qf->metadata->seed,
															 buffer, buffer_len);

	if (init_size > buffer_len)
		return init_size;

	if (qf->runtimedata->auto_resize)
		qf_set_auto_resize(&new_qf, true);

	// copy keys from qf into new_qf
	QFi qfi;
	qf_iterator_from_position(qf, &qfi, 0);
	do {
		uint64_t key, value, count;
		//qfi_get_hash(&qfi, &key, &count);
		qfi_next(&qfi);
		int ret = qf_insert(&new_qf, key, value, count, QF_NO_LOCK | QF_KEY_IS_HASH);
		if (ret < 0) {
			fprintf(stderr, "Failed to insert key: %ld into the new CQF.\n", key);
			abort();
		}
	} while(!qfi_end(&qfi));

	qf_free(qf);
	memcpy(qf, &new_qf, sizeof(QF));

	return init_size;
}

void qf_set_auto_resize(QF* qf, bool enabled)
{
	if (enabled)
		qf->runtimedata->auto_resize = 1;
	else
		qf->runtimedata->auto_resize = 0;
}

/*
key - 
*/
int qf_insert_ret(QF *qf, uint64_t key, uint64_t count, uint64_t *ret_index, uint64_t *ret_hash, int *ret_hash_len, uint8_t flags)
{
	// We fill up the CQF up to 95% load factor.
	// This is a very conservative check.
	//if (qf_get_num_occupied_slots(qf) >= qf->metadata->nslots * 0.95) {
	if (qf->metadata->noccupied_slots >= qf->metadata->nslots * 0.95) {
		if (qf->runtimedata->auto_resize) {
			/*fprintf(stdout, "Resizing the CQF.\n");*/
			if (qf->runtimedata->container_resize(qf, qf->metadata->nslots * 2) < 0)
			{
				fprintf(stderr, "Resizing the failed.\n");
				return QF_NO_SPACE;
			}
		} else {
			return QF_NO_SPACE;
		}
	}
	if (count == 0)
		return 0;

	if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
		if (qf->metadata->hash_mode == QF_HASH_DEFAULT)
			key = MurmurHash64A(((void *)&key), sizeof(key), qf->metadata->seed);
		else if (qf->metadata->hash_mode == QF_HASH_INVERTIBLE)
			key = hash_64(key, -1ULL);
	}
	//uint64_t hash = ((key << qf->metadata->value_bits) | (value & BITMASK(qf->metadata->value_bits)));// % qf->metadata->range;
	uint64_t hash = key;
	
	int ret = insert(qf, hash, count, ret_index, ret_hash, ret_hash_len, flags);
	if (ret != 0) record(qf, "insert", hash, -1);
	return ret;
}

int qf_insert(QF *qf, uint64_t key, uint64_t value, uint64_t count, uint8_t flags)
{
	// We fill up the CQF up to 95% load factor.
	// This is a very conservative check.
	if (qf_get_num_occupied_slots(qf) >= qf->metadata->nslots * 0.95) {
		if (qf->runtimedata->auto_resize) {
			/*fprintf(stdout, "Resizing the CQF.\n");*/
			if (qf->runtimedata->container_resize(qf, qf->metadata->nslots * 2) < 0)
			{
				fprintf(stderr, "Resizing the failed.\n");
				return QF_NO_SPACE;
			}
		} else
			return QF_NO_SPACE;
	}
	if (count == 0)
		return 0;

	if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
		if (qf->metadata->hash_mode == QF_HASH_DEFAULT)
			key = MurmurHash64A(((void *)&key), sizeof(key), qf->metadata->seed);
		else if (qf->metadata->hash_mode == QF_HASH_INVERTIBLE)
			key = hash_64(key, -1ULL);
	} else {
    printf("Skipping hash\n");
  }
	uint64_t hash = ((key << qf->metadata->value_bits) | (value & BITMASK(qf->metadata->value_bits)));
	
	uint64_t found_index, found_hash;
	int found_hash_len;
	int ret = insert(qf, hash, count, &found_index, &found_hash, &found_hash_len, flags);

	return ret;
}

int qf_set_count(QF *qf, uint64_t key, uint64_t value, uint64_t count, uint8_t
								 flags)
{
	return 0;
	/*if (count == 0)
		return 0;

	uint64_t cur_count = qf_count_key_value(qf, key, value, flags);
	int64_t delta = count - cur_count;

	int ret;
	if (delta == 0)
		ret = 0;
	else if (delta > 0)
		ret = qf_insert(qf, key, value, delta, flags);
	else
		ret = qf_remove(qf, key, value, labs(delta), flags);

	return ret;*/
}

int qf_remove(QF *qf, uint64_t key, uint64_t *ret_hash, int *ret_hash_len, uint8_t flags)
{
	if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
		if (qf->metadata->hash_mode == QF_HASH_DEFAULT)
			key = MurmurHash64A(((void *)&key), sizeof(key), qf->metadata->seed);
		else if (qf->metadata->hash_mode == QF_HASH_INVERTIBLE)
			key = hash_64(key, -1ULL);
	}
	uint64_t hash =	key;
	int ret = _remove(qf, hash, ret_hash, ret_hash_len, flags);
	record(qf, "remove", hash, -1);
	return ret;
}

// TODO: add a return value for the "value" bits attached to the fingerprint
uint64_t qf_query(const QF *qf, uint64_t key, uint64_t *ret_index, uint64_t *ret_hash, int *ret_hash_len, uint8_t flags)
{
	//printf("query start\n");
	// Convert key to hash
	if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
		if (qf->metadata->hash_mode == QF_HASH_DEFAULT)
			key = MurmurHash64A(((void *)&key), sizeof(key), qf->metadata->seed);
		else if (qf->metadata->hash_mode == QF_HASH_INVERTIBLE)
			key = hash_64(key, -1ULL);
	}
	//uint64_t hash = (key << qf->metadata->value_bits) | (value & BITMASK(qf->metadata->value_bits));
	uint64_t hash = key;
	uint64_t hash_remainder   = hash & BITMASK(qf->metadata->bits_per_slot);
	uint64_t hash_bucket_index = (hash >> qf->metadata->bits_per_slot) & BITMASK(qf->metadata->quotient_bits);

	// If no one wants this slot, we can already say for certain the item is not in the filter
	if (!is_occupied(qf, hash_bucket_index))
		return 0;

	// Otherwise, find the start of the run (all the items that want that slot) and parse for the remainder we're looking for
	uint64_t runstart_index = hash_bucket_index == 0 ? 0 : run_end(qf, hash_bucket_index - 1) + 1;
	if (runstart_index < hash_bucket_index)
		runstart_index = hash_bucket_index;

	// "optimized" query
	uint64_t current_index = runstart_index;
	do { // for each slot containing the start of an item:
		if (get_slot(qf, current_index) == hash_remainder) { // if first slot matches, check remaining extensions
			uint64_t ext, count;
			int ext_len, count_len;
			get_slot_info(qf, current_index, &ext, &ext_len, &count, &count_len);
			if (((hash >> (qf->metadata->quotient_bits + qf->metadata->bits_per_slot)) & BITMASK(qf->metadata->bits_per_slot * ext_len)) == ext) { // if extensions match, return the count
				if (ret_index != NULL) *ret_index = current_index;
				if (ret_hash != NULL) *ret_hash = (hash & BITMASK(qf->metadata->quotient_bits + qf->metadata->bits_per_slot)) | (ext << (qf->metadata->quotient_bits + qf->metadata->bits_per_slot));
				if (ret_hash_len != NULL) *ret_hash_len = (qf->metadata->bits_per_slot * ext_len) + qf->metadata->quotient_bits + qf->metadata->bits_per_slot;
				return count;
			}
			if (is_runend(qf, current_index++)) break; // if extensions don't match, stop if end of run, skip to next item otherwise
			current_index += ext_len + count_len;
		}
		else { // if first slot doesn't match, stop if end of run, skip to next item otherwise
			if (is_runend(qf, current_index++)) break;
			while (is_extension_or_counter(qf, current_index)) current_index++;
		}
	} while (current_index < qf->metadata->xnslots); // stop if reached the end of all items (should never actually reach this point because should stop at the runend)

	return 0;
}

static inline int get_slot_info(const QF *qf, uint64_t index, uint64_t *ext, int *ext_slots, uint64_t *count, int *count_slots) {
	assert(!is_extension_or_counter(qf, index));

	int curr = ++index;
	if (ext != NULL) {
		*ext = 0;
		while (is_extension(qf, curr)) {
			*ext |= get_slot(qf, curr) << ((curr - index) * qf->metadata->bits_per_slot);
			curr++;
		}
		if (ext_slots != NULL) *ext_slots = curr - index;
	}
	else while (is_extension(qf, index++));

	index = curr;
	if (count != NULL) {
		*count = 0;
		if (!is_counter(qf, curr)) {
			*count = 1;
			if (count_slots != NULL) *count_slots = 0;
		}
		while (is_counter(qf, curr)) {
			*count |= get_slot(qf, curr) << ((curr - index) * qf->metadata->bits_per_slot);
			curr++;
		}
		if (count_slots != NULL) *count_slots = curr - index;
	}
	return 1;
}

static inline int adapt(QF *qf, uint64_t index, uint64_t hash_bucket_index, uint64_t hash, uint64_t other_hash, uint64_t *ret_hash) {
	uint64_t ext, count;
	int ext_len, count_len;
	// figure out how many extensions there currently are
	if (!get_slot_info(qf, index, &ext, &ext_len, &count, &count_len)) return 0;
	assert((hash & BITMASK(qf->metadata->quotient_bits + qf->metadata->bits_per_slot)) == (get_slot(qf, index) | (hash_bucket_index << qf->metadata->bits_per_slot)));
	int ext_bits = qf->metadata->bits_per_slot * ext_len;
	*ret_hash = hash & BITMASK(ext_bits + qf->metadata->quotient_bits + qf->metadata->bits_per_slot);
	int slots_used = ext_len + 1;
	// get the bits for the next extension
	hash >>= ext_bits + qf->metadata->quotient_bits;
	other_hash >>= ext_bits + qf->metadata->quotient_bits;

	do {
		hash >>= qf->metadata->bits_per_slot;
		other_hash >>= qf->metadata->bits_per_slot;

		uint64_t empty_slot_index = find_first_empty_slot(qf, index + slots_used);
		if (empty_slot_index >= qf->metadata->xnslots) {
			printf("adapt hit xnslots\n");
			return QF_NO_SPACE; // maybe should do something about the now extraneous slots? allows for false negative
		}

		shift_remainders(qf, index + slots_used, empty_slot_index);

		set_slot(qf, index + slots_used, hash & BITMASK(qf->metadata->bits_per_slot));
		*ret_hash |= (hash & BITMASK(qf->metadata->bits_per_slot)) << (ext_bits + qf->metadata->quotient_bits + qf->metadata->bits_per_slot);

		shift_runends(qf, index + slots_used, empty_slot_index - 1, 1);

		uint64_t i;
		for (i = hash_bucket_index / QF_SLOTS_PER_BLOCK + 1; i <= empty_slot_index / QF_SLOTS_PER_BLOCK; i++) {
			if (get_block(qf, i)->offset < BITMASK(8 * sizeof(qf->blocks[0].offset))) get_block(qf, i)->offset++;
		}

		METADATA_WORD(qf, extensions, index + slots_used) |= 1ULL << ((index + slots_used) % 64);
		//modify_metadata(&qf->runtimedata->pc_noccupied_slots, 1);
		qf->metadata->noccupied_slots++;
		slots_used++;
		ext_bits += qf->metadata->bits_per_slot;
	} while (((hash & BITMASK(qf->metadata->bits_per_slot)) == (other_hash & BITMASK(qf->metadata->bits_per_slot))) && (ext_bits + qf->metadata->quotient_bits + qf->metadata->bits_per_slot < 64));

	return ext_bits + qf->metadata->quotient_bits + qf->metadata->bits_per_slot;
}

/*	index is the index of the fingerprint to adapt (should have been returned in ret_index by qf_query or qf_insert_ret)
	hash is the full hash of the item to extend the fingerprint of
	other_hash is the full hash of the false positive item; qf_adapt will extend the fingerprint until it differentiates from other_hash
	ret_hash will contain the resulting fingerprint after extending
	returns the length of the resulting fingerprint
*/
int qf_adapt(QF *qf, uint64_t index, uint64_t key, uint64_t other_key, uint64_t *ret_hash, uint8_t flags) {
	uint64_t hash = key, other_hash = other_key;
	if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
		if (qf->metadata->hash_mode == QF_HASH_DEFAULT) {
			hash = MurmurHash64A(((void *)&key), sizeof(key), qf->metadata->seed);
			other_hash = MurmurHash64A(((void *)&other_key), sizeof(other_key), qf->metadata->seed);
		}
		else if (qf->metadata->hash_mode == QF_HASH_INVERTIBLE) {
			hash = hash_64(key, -1ULL);
			other_hash = hash_64(other_key, -1ULL);
		}
	}

	if (hash == other_hash) return 0;
	int ret = adapt(qf, index, (hash % qf->metadata->range) >> qf->metadata->bits_per_slot, hash, other_hash, ret_hash);
	record(qf, "adapt", hash, -1);
	return ret;
}

int qf_adapt_using_ll_table(QF *qf, uint64_t orig_key, uint64_t fp_key, uint64_t minirun_rank, uint8_t flags) {
	uint64_t hash;
	if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
		if (qf->metadata->hash_mode == QF_HASH_DEFAULT) {
			hash = MurmurHash64A(((void *)&fp_key), sizeof(fp_key), qf->metadata->seed);
		}
		else if (qf->metadata->hash_mode == QF_HASH_INVERTIBLE) {
			hash = hash_64(fp_key, -1ULL);
		}
	}
	else hash = fp_key;

	uint64_t hash_remainder = hash & BITMASK(qf->metadata->bits_per_slot);
	uint64_t hash_bucket_index = (hash >> qf->metadata->bits_per_slot) & BITMASK(qf->metadata->quotient_bits);
	if (!is_occupied(qf, hash_bucket_index)) return 0;
	
	uint64_t current_index = hash_bucket_index == 0 ? 0 : run_end(qf, hash_bucket_index - 1) + 1;
	int curr_minirun_rank = 0;

	uint64_t count_info, hash_info;
	int count_slots, hash_slots;
	do {
		if (get_slot(qf, current_index) < hash_remainder) {
			while (is_extension_or_counter(qf, ++current_index));
		}
		else if (get_slot(qf, current_index) == hash_remainder) {
			get_slot_info(qf, current_index, &hash_info, &hash_slots, &count_info, &count_slots);

			if (curr_minirun_rank == minirun_rank) {
				qf_adapt(qf, current_index, orig_key, fp_key, &hash_info, flags);

				return 1;
			}

			if (is_runend(qf, current_index)) break;
			current_index += count_slots + hash_slots + 1;
			curr_minirun_rank++;
		}
		else break;
	} while (current_index < qf->metadata->xnslots);

	return 0;
}


enum qf_hashmode qf_get_hashmode(const QF *qf) {
	return qf->metadata->hash_mode;
}
uint64_t qf_get_hash_seed(const QF *qf) {
	return qf->metadata->seed;
}
__uint128_t qf_get_hash_range(const QF *qf) {
	return qf->metadata->range;
}

bool qf_is_auto_resize_enabled(const QF *qf) {
	if (qf->runtimedata->auto_resize == 1)
		return true;
	return false;
}
uint64_t qf_get_total_size_in_bytes(const QF *qf) {
	return qf->metadata->total_size_in_bytes;
}
uint64_t qf_get_nslots(const QF *qf) {
	return qf->metadata->nslots;
}
uint64_t qf_get_num_occupied_slots(const QF *qf) {
	//pc_sync(&qf->runtimedata->pc_noccupied_slots);
	return qf->metadata->noccupied_slots;
}

uint64_t qf_get_num_key_bits(const QF *qf) {
	return qf->metadata->key_bits;
}
uint64_t qf_get_num_value_bits(const QF *qf) {
	return qf->metadata->value_bits;
}
uint64_t qf_get_num_key_remainder_bits(const QF *qf) {
	return qf->metadata->key_remainder_bits;
}
uint64_t qf_get_bits_per_slot(const QF *qf) {
	return qf->metadata->bits_per_slot;
}

uint64_t qf_get_sum_of_counts(const QF *qf) {
	pc_sync(&qf->runtimedata->pc_nelts);
	return qf->metadata->nelts;
}
uint64_t qf_get_num_distinct_key_value_pairs(const QF *qf) {
	pc_sync(&qf->runtimedata->pc_ndistinct_elts);
	return qf->metadata->ndistinct_elts;
}

void qf_sync_counters(const QF *qf) {
	pc_sync(&qf->runtimedata->pc_ndistinct_elts);
	pc_sync(&qf->runtimedata->pc_nelts);
	pc_sync(&qf->runtimedata->pc_noccupied_slots);
}

/* initialize the iterator at the run corresponding
 * to the position index
 */
int64_t qf_iterator_from_position(const QF *qf, QFi *qfi, uint64_t position)
{
	if (position == 0xffffffffffffffff) {
		qfi->current = 0xffffffffffffffff;
		qfi->qf = qf;
		return QFI_INVALID;
	}
	assert(position < qf->metadata->nslots);
	if (!is_occupied(qf, position)) {
		uint64_t block_index = position / QF_SLOTS_PER_BLOCK;
		uint64_t idx = bitselectv(get_block(qf, block_index)->occupieds[0], position, 0);
		if (idx == 64) {
			while(idx == 64 && block_index < qf->metadata->nblocks) {
				block_index++;
				idx = bitselect(get_block(qf, block_index)->occupieds[0], 0);
			}
		}
		position = block_index * QF_SLOTS_PER_BLOCK + idx;
	}

	qfi->qf = qf;
	qfi->num_clusters = 0;
	qfi->run = position;
	qfi->current = position == 0 ? 0 : run_end(qfi->qf, position-1) + 1;
	if (qfi->current < position)
		qfi->current = position;
  qfi->intra_slot_offset = qf->metadata->key_remainder_bits;
  qfi->current_remainder = get_slot(qfi->qf, qfi->current) & BITMASK(qf->metadata->key_remainder_bits);
  qfi->current_memento = (get_slot(qfi->qf, qfi->current) >> qfi->intra_slot_offset) & BITMASK(qf->metadata->value_bits);
  qfi->num_extensions = 0;

  if (is_extension(qfi->qf, qfi->current)) {
    abort(); // TODO(chesetti): Implement extensions in iterator.
    // First extension is memento bits sized.
    // Check for further extensions and update current, current_remainder and current_memento.
  }

#ifdef LOG_CLUSTER_LENGTH
	qfi->c_info = (cluster_data* )calloc(qf->metadata->nslots/32,
																			 sizeof(cluster_data));
	if (qfi->c_info == NULL) {
		perror("Couldn't allocate memory for c_info.");
		exit(EXIT_FAILURE);
	}
	qfi->cur_start_index = position;
	qfi->cur_length = 1;
#endif

	if (qfi->current >= qf->metadata->nslots)
		return QFI_INVALID;
	return qfi->current;
}

/* DO NOT USE
 */
int64_t qf_iterator_from_key_value(const QF *qf, QFi *qfi, uint64_t key,
																	 uint64_t value, uint8_t flags)
{
  abort(); // DO NOT USE.
	if (key >= qf->metadata->range) {
		qfi->current = 0xffffffffffffffff;
		qfi->qf = qf;
		return QFI_INVALID;
	}

	qfi->qf = qf;
	qfi->num_clusters = 0;

	if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
		if (qf->metadata->hash_mode == QF_HASH_DEFAULT)
			key = MurmurHash64A(((void *)&key), sizeof(key), qf->metadata->seed);
		else if (qf->metadata->hash_mode == QF_HASH_INVERTIBLE)
			key = hash_64(key, -1ULL);
	}
	uint64_t hash = (key << qf->metadata->value_bits) | (value & BITMASK(qf->metadata->value_bits));

	uint64_t hash_remainder   = hash & BITMASK(qf->metadata->bits_per_slot);
	uint64_t hash_bucket_index = hash >> qf->metadata->bits_per_slot;
	bool flag = false;

	// If a run starts at "position" move the iterator to point it to the
	// smallest key greater than or equal to "hash".
	if (is_occupied(qf, hash_bucket_index)) {
		uint64_t runstart_index = hash_bucket_index == 0 ? 0 : run_end(qf,
																																	 hash_bucket_index-1)
			+ 1;
		if (runstart_index < hash_bucket_index)
			runstart_index = hash_bucket_index;
		uint64_t current_remainder, current_count, current_end;
		do {
			//printf("2517");
			//current_end = decode_counter(qf, runstart_index, &current_remainder, &current_count);
			if (current_remainder >= hash_remainder) {
				flag = true;
				break;
			}
			runstart_index = current_end + 1;
		} while (!is_runend(qf, current_end));
		// found "hash" or smallest key greater than "hash" in this run.
		if (flag) {
			qfi->run = hash_bucket_index;
			qfi->current = runstart_index;
		}
	}
	// If a run doesn't start at "position" or the largest key in the run
	// starting at "position" is smaller than "hash" then find the start of the
	// next run.
	if (!is_occupied(qf, hash_bucket_index) || !flag) {
		uint64_t position = hash_bucket_index;
		assert(position < qf->metadata->nslots);
		uint64_t block_index = position / QF_SLOTS_PER_BLOCK;
		uint64_t idx = bitselect(get_block(qf, block_index)->occupieds[0], 0);
		if (idx == 64) {
			while(idx == 64 && block_index < qf->metadata->nblocks) {
				block_index++;
				idx = bitselect(get_block(qf, block_index)->occupieds[0], 0);
			}
		}
		position = block_index * QF_SLOTS_PER_BLOCK + idx;
		qfi->run = position;
		qfi->current = position == 0 ? 0 : run_end(qfi->qf, position-1) + 1;
		if (qfi->current < position)
			qfi->current = position;
	}

	if (qfi->current >= qf->metadata->nslots)
		return QFI_INVALID;
	return qfi->current;
}

// TODO: the current schema uses ext_len to indicate the number of slots used for extensions.
// I want to eventually change this mean the number of bits in the extension.
// This will allow qf_resize_malloc to more smartly allocate the proper number of slots for an extension in the new filter.
// eg. If a filter with 4 rbits goes to 3 rbits, and an item has 3 extensions,
//     the current system will see there are 3 extension slots, and the resulting fingerprint will too, dropping 3 bits.
//     However, if ext_len is known to be 12, the 3 dropped bits could be put in a new extension, losing no bits.
static inline int qfi_get(const QFi *qfi, uint64_t *rem, uint64_t *ext, int *ext_len, uint64_t *count)
{
	if (qfi_end(qfi)) return QFI_INVALID;

	int count_len;
	get_slot_info(qfi->qf, qfi->current, ext, ext_len, count, &count_len);
	*rem = get_slot(qfi->qf, qfi->current);

	return 0;
}

// DO NOT USE
int qfi_get_key(const QFi *qfi, uint64_t *key, uint64_t *value, uint64_t
								*count)
{
  abort(); // DO NOT USE
	*key = *value = *count = 0;
	int ret = 0;// = qfi_get(qfi, key, count);
	if (ret == 0) {
		if (qfi->qf->metadata->hash_mode == QF_HASH_DEFAULT) {
			*key = 0; *value = 0; *count = 0;
			return QF_INVALID;
		} else if (qfi->qf->metadata->hash_mode == QF_HASH_INVERTIBLE)
			*key = hash_64i(*key, -1ULL);
	}

	return ret;
}

int qfi_get_hash(const QFi *qfi, uint64_t *rem, uint64_t *ext, int *ext_len, uint64_t *count)
{
   abort(); // DO NOT USE.
	*rem = *ext = *ext_len = *count = 0;
	return qfi_get(qfi, rem, ext, ext_len, count);
}

int qfi_get_memento_hash(const QFi *qfi, uint64_t *hash)
{
  *hash = qfi->current_memento | (qfi->current_remainder << qfi->qf->metadata->value_bits);
  if (qfi->num_extensions > 0) {
    abort();
  } else {
    *hash = *hash | (qfi->run << qfi->qf->metadata->bits_per_slot);
  }
  return 0;
}

int qfi_get_memento(const QFi *qfi, uint64_t *memento)
{
  *memento = qfi->current_memento;
  return 0;
}

static inline int qfi_start_new_keepsake(QFi* qfi)
{
  qfi->intra_slot_offset = 0;
  if (qfi->current >= qfi->qf->metadata->xnslots)
    return QFI_INVALID;

  assert(is_keepsake_or_quotient_runend(qfi->qf, qfi->current - 1));

  if (is_runend(qfi->qf, qfi->current - 1)) {
    qfi->run++;
    uint64_t block_index = (qfi->run / QF_SLOTS_PER_BLOCK);
    uint64_t idx = bitselectv(get_block(qfi->qf, block_index)->occupieds[0], qfi->run, 0);
    if (idx == 64) {
      while (idx == 64 && block_index < qfi->qf->metadata->nblocks) {
        block_index++;
        idx = bitselect(get_block(qfi->qf, block_index)->occupieds[0], 0);
      }
    }
    qfi->run = block_index * QF_SLOTS_PER_BLOCK + idx;
    qfi->current = qfi->run == 0 ? 0 : run_end(qfi->qf, qfi->run - 1) + 1;
    qfi->current_remainder = get_slot(qfi->qf, qfi->current) & BITMASK(qfi->qf->metadata->key_remainder_bits);
    // TODO(chesetti): Handle case of extension here.
    qfi->intra_slot_offset += qfi->qf->metadata->key_remainder_bits;
    qfi->current_memento = (get_slot(qfi->qf, qfi->current) >> qfi->intra_slot_offset) & BITMASK(qfi->qf->metadata->value_bits);
    qfi->num_extensions = 0;
    if (qfi->current >= qfi->qf->metadata->xnslots)
      return QFI_INVALID;
    return 0;
  } else if (is_keepsake_or_quotient_runend(qfi->qf, qfi->current - 1)) {
    qfi->current_remainder = get_slot(qfi->qf, qfi->current) & BITMASK(qfi->qf->metadata->key_remainder_bits);
    qfi->intra_slot_offset += qfi->qf->metadata->key_remainder_bits;
    qfi->current_memento = (get_slot(qfi->qf, qfi->current) >> qfi->intra_slot_offset) & BITMASK(qfi->qf->metadata->value_bits);
    qfi->num_extensions = 0;
    return 0;
  }
  return QFI_INVALID;
}


static inline int qfi_next_keepsake(QFi *qfi) {
  // From qfi->current, find the next runend bit.
  // Assumes valid iterator (not at qfi_end) positioned at start of quotient run.
  int next_runend_block = qfi->current / QF_SLOTS_PER_BLOCK;
	int next_runend_offset = bitselectv(get_block(qfi->qf, next_runend_block)->runends[0], qfi->current, 0);
  if (next_runend_offset == 64) {
    while (next_runend_offset == 64 && next_runend_block < qfi->qf->metadata->nblocks) {
      next_runend_block++;
	    next_runend_offset = bitselectv(get_block(qfi->qf, next_runend_block)->runends[0], 0, 0);
    }
  }
  qfi->current = next_runend_block * QF_SLOTS_PER_BLOCK + next_runend_offset + 1;
  return qfi_start_new_keepsake(qfi);
}

int qfi_next(QFi *qfi) {
  if (qfi_end(qfi))
    return QFI_INVALID;

  // Move the intra_slot_offset ahead. 
  // Try to detect if  we just started a new run.
  qfi->intra_slot_offset += qfi->qf->metadata->value_bits;
  if (qfi->intra_slot_offset > qfi->qf->metadata->bits_per_slot) {
    // In this case, a new run cannot start in this current slot.
    // The previous memento was spanning multiple slots.
    assert(!is_keepsake_or_quotient_runend(qfi->qf, qfi->current));
    qfi->current++; 
    qfi->intra_slot_offset -= qfi->qf->metadata->bits_per_slot;
  } else if (qfi->intra_slot_offset == qfi->qf->metadata->bits_per_slot) {
    // Here, the last memento we returned was aligned with the slot end.
    // So we, check if the new slot starts a new keepsake.
    qfi->current++; 
    qfi->intra_slot_offset = 0;
    if (qfi_end(qfi))
      return QFI_INVALID;
    if(is_keepsake_or_quotient_runend(qfi->qf, qfi->current-1)) {
      return qfi_start_new_keepsake(qfi);
    }
  }

  int next_memento_spans_multiple_slots = (qfi->intra_slot_offset + qfi->qf->metadata->value_bits > qfi->qf->metadata->bits_per_slot) ? 1 : 0;
  uint64_t next_memento = 0;
  if (next_memento_spans_multiple_slots && is_keepsake_or_quotient_runend(qfi->qf, qfi->current)) {
    // Not enough bits for a new memento. point to the new keepsake.
    qfi->current++;
    qfi->intra_slot_offset = 0;
    return qfi_start_new_keepsake(qfi);
  } 
  if (next_memento_spans_multiple_slots) {
    uint64_t bits_in_current_slot = qfi->qf->metadata->bits_per_slot - qfi->intra_slot_offset;
    uint64_t bits_in_next_slot = qfi->qf->metadata->value_bits - bits_in_current_slot;
    next_memento = get_slot(qfi->qf, qfi->current) >> qfi->intra_slot_offset;
    next_memento = next_memento | ((get_slot(qfi->qf, qfi->current + 1) & BITMASK(bits_in_next_slot)) << bits_in_current_slot);
  } else {
    next_memento = (get_slot(qfi->qf, qfi->current) >> qfi->intra_slot_offset) & BITMASK(qfi->qf->metadata->value_bits);
  }

  if (next_memento <= qfi->current_memento) {
    // Should not happen, means we could have ended the current slot here.
    assert(!next_memento_spans_multiple_slots); 
    qfi->current++;
    return qfi_start_new_keepsake(qfi);
  } else {
    qfi->current_memento = next_memento;
  }
  return 0;
}


static inline int _qfi_next(QFi *qfi) {
  if (qfi_end(qfi))
    return QFI_INVALID;

  // Move the intra_slot_offset ahead. 
  // Try to detect if  we just started a new run.
  qfi->intra_slot_offset += qfi->qf->metadata->value_bits;
  if (qfi->intra_slot_offset > qfi->qf->metadata->bits_per_slot) {
    // In this case, a new run cannot start in this current slot.
    // The previous memento was spanning multiple slots.
    assert(!is_keepsake_or_quotient_runend(qfi->qf, qfi->current));
    qfi->current++; 
    qfi->intra_slot_offset -= qfi->qf->metadata->bits_per_slot;
  } else if (qfi->intra_slot_offset == qfi->qf->metadata->bits_per_slot) {
    // Here, the last memento we returned was aligned with the slot end.
    // So we, check if the new slot starts a new keepsake.
    qfi->current++; 
    qfi->intra_slot_offset = 0;
    if (qfi_end(qfi))
      return QFI_INVALID;
    if(is_keepsake_or_quotient_runend(qfi->qf, qfi->current-1)) {
      return qfi_start_new_keepsake(qfi);
    }
  }

  int next_memento_spans_multiple_slots = (qfi->intra_slot_offset + qfi->qf->metadata->value_bits > qfi->qf->metadata->bits_per_slot) ? 1 : 0;
  uint64_t next_memento = 0;
  if (next_memento_spans_multiple_slots && is_keepsake_or_quotient_runend(qfi->qf, qfi->current)) {
    // Not enough bits for a new memento. point to the new keepsake.
    qfi->current++;
    qfi->intra_slot_offset = 0;
    return qfi_start_new_keepsake(qfi);
  } 
  if (next_memento_spans_multiple_slots) {
    uint64_t bits_in_current_slot = qfi->qf->metadata->bits_per_slot - qfi->intra_slot_offset;
    uint64_t bits_in_next_slot = qfi->qf->metadata->value_bits - bits_in_current_slot;
    next_memento = get_slot(qfi->qf, qfi->current) >> qfi->intra_slot_offset;
    next_memento = next_memento | ((get_slot(qfi->qf, qfi->current + 1) & BITMASK(bits_in_next_slot)) << bits_in_current_slot);
  } else {
    next_memento = (get_slot(qfi->qf, qfi->current) >> qfi->intra_slot_offset) & BITMASK(qfi->qf->metadata->value_bits);
  }

  if (next_memento <= qfi->current_memento) {
    // Should not happen, means we could have ended the current slot here.
    assert(!next_memento_spans_multiple_slots); 
    qfi->current++;
    return qfi_start_new_keepsake(qfi);
  } else {
    qfi->current_memento = next_memento;
  }
  return 0;
}

bool qfi_end(const QFi *qfi)
{
	if (qfi->current >= qfi->qf->metadata->xnslots /*&& is_runend(qfi->qf, qfi->current)*/)
		return true;
	return false;
}

static inline bool _qfi_end(const QFi *qfi)
{
	if (qfi->current >= qfi->qf->metadata->xnslots /*&& is_runend(qfi->qf, qfi->current)*/)
		return true;
	return false;
}

static inline int _finger_cmp(uint64_t bits_per_item, uint64_t rema, uint64_t exta, int extlena, uint64_t remb, uint64_t extb, int extlenb) {
	if (rema < remb) return -1;
	else if (remb < rema) return 1;
	while (exta != extb) {
		uint64_t a = exta & BITMASK(bits_per_item), b = extb & BITMASK(bits_per_item);
		if (a < b) return -1;
		if (b < a) return 1;
		exta >>= bits_per_item;
		extb >>= bits_per_item;
	}
	if (extlena == extlenb) return 0;
	if (extlena < extlenb) return -1;
	else return 1;
}

/* Specifically for use while merging
 * Inserts a full item at the given index
 * Assumes all of the slots from this index onwards are unused
 */
static inline uint64_t _merge_insert(QF *qf, uint64_t index, uint64_t run, uint64_t rem, uint64_t ext, uint64_t ext_len, uint64_t count) {
	uint64_t current = index;
	set_slot(qf, current++, rem);
	for (int i = 0; i < ext_len; i++) {
		set_slot(qf, current, ext & BITMASK(qf->metadata->bits_per_slot));
		ext >>= qf->metadata->bits_per_slot;
		METADATA_WORD(qf, extensions, current) |= (1ULL << (current % QF_SLOTS_PER_BLOCK));
		current++;
	}
	if (count > 1) while (count > 0) {
		set_slot(qf, current, count & BITMASK(qf->metadata->bits_per_slot));
		count >>= qf->metadata->bits_per_slot;
		METADATA_WORD(qf, extensions, current) |= (1ULL << (current % QF_SLOTS_PER_BLOCK));
		METADATA_WORD(qf, runends, current) |= (1ULL << (current % QF_SLOTS_PER_BLOCK));
		current++;
	}
	uint64_t bucket_block = run / QF_SLOTS_PER_BLOCK;
	uint64_t current_block = (current - 1) / QF_SLOTS_PER_BLOCK;
	if (current_block != bucket_block) {
		for (int i = index; i < current; i++) {
			if (i / QF_SLOTS_PER_BLOCK != bucket_block) {
				get_block(qf, i / QF_SLOTS_PER_BLOCK)->offset++;
			}
		}
	}
	return current;
}

int qf_resize_malloc(QF *qf, uint64_t nslots) {
	if (qf->metadata->nslots > nslots) return 0; // not yet supporting resizing to make smaller, because requires extra information for extensions

	QF new_qf;
	if (!qf_malloc(&new_qf, nslots, qf->metadata->key_bits, qf->metadata->value_bits, qf->metadata->hash_mode, qf->metadata->seed)) return 0;
	if (qf->runtimedata->auto_resize) qf_set_auto_resize(&new_qf, true);

	uint64_t current_run = 0;
	uint64_t current_index = 0;
	uint64_t last_index = -1;

	QFi qfi;
	qf_iterator_from_position(qf, &qfi, 0);

	uint64_t rem, ext, count;
	int extlen;
	qfi_get_hash(&qfi, &rem, &ext, &extlen, &count);
	if (qfi.run == 0) METADATA_WORD(&new_qf, occupieds, 0) |= 1;
	while (!qfi_end(&qfi)) {
		if (qfi.run != current_run) {
			if (last_index != -1) METADATA_WORD(&new_qf, runends, last_index) |= (1ULL << (last_index % QF_SLOTS_PER_BLOCK));
			current_run = qfi.run;
			METADATA_WORD(&new_qf, occupieds, current_run) |= (1ULL << (current_run % QF_SLOTS_PER_BLOCK));
			if (current_index < current_run) current_index = current_run;
		}
		last_index = current_index;
		current_index = _merge_insert(qf, current_index, current_run, rem, ext, extlen, count);
	}
	if (last_index != -1) METADATA_WORD(qf, runends, last_index) |= (1ULL << (last_index % QF_SLOTS_PER_BLOCK));

	qf_free(qf);
	memcpy(qf, &new_qf, sizeof(QF));

	return 1;
}


void qf_merge(const QF *qfa, const QF *qfb, QF *qfc) {
	qf_merge_ret(qfa, qfb, qfc, NULL, NULL, NULL);
}

/* Takes two filters, qfa and qfb, and merges their contents into qfc, which is assumed to be empty and large enough to hold all the items.
 * Returns a list of the collided elements.
 * That is, every fingerprint in an AQF must be unique. If a fingerprint in qfa matches one from qfb, their counts are simply combined.
 * However, their fingerprint will be added to the list of collided fingerprints.
 * The user should take this list and use it to go back through and fix the fingerprints so that they are unique.
 * Otherwise, the filter could have false negatives.
 * I will eventually be adding a function to allow the user to do this automatically.
 */
void qf_merge_ret(const QF *qfa, const QF *qfb, QF *qfc, uint64_t **coll_hash, int **coll_len, int *coll_amt) {
	assert(qfc->metadata->noccupied_slots == 0);
	assert(qfc->metadata->xnslots > qfa->metadata->noccupied_slots + qfb->metadata->noccupied_slots);
	assert(qfa->metadata->bits_per_slot == qfb->metadata->bits_per_slot && qfb->metadata->bits_per_slot == qfc->metadata->bits_per_slot);

	uint64_t current_run = 0;
	uint64_t current_index = 0;
	uint64_t last_index = -1;

	QFi qfia, qfib;
	qf_iterator_from_position(qfa, &qfia, 0);
	qf_iterator_from_position(qfb, &qfib, 0);

	if (qfa->metadata->hash_mode != qfc->metadata->hash_mode &&
			qfa->metadata->seed != qfc->metadata->seed &&
			qfb->metadata->hash_mode  != qfc->metadata->hash_mode &&
			qfb->metadata->seed  != qfc->metadata->seed) {
		fprintf(stderr, "Output QF and input QFs do not have the same hash mode or seed.\n");
		exit(1);
	}

	uint64_t coll_size = 1 << 8;
	if (coll_hash) {
		*coll_amt = 0;
		*coll_hash = malloc(coll_size * sizeof(uint64_t));
		*coll_len = malloc(coll_size * sizeof(int));
	}

	uint64_t rema, exta, counta;
	int extlena;
	uint64_t remb, extb, countb;
	int extlenb;
	qfi_get_hash(&qfia, &rema, &exta, &extlena, &counta);
	qfi_get_hash(&qfib, &remb, &extb, &extlenb, &countb);
	if (qfia.run == 0 || qfib.run == 0) METADATA_WORD(qfc, occupieds, 0) |= 1;
	do {
		if (qfia.run == current_run) {
			// if both qfa and qfb have more items for this run, add the item with the lower fingerprint
			if (qfib.run == current_run) {
				last_index = current_index;
				switch (_finger_cmp(qfc->metadata->bits_per_slot, rema, exta, extlena, remb, extb, extlenb)) {
					case 0:
						current_index = _merge_insert(qfc, current_index, current_run, rema, exta, extlena, counta + countb);
						if (coll_hash) {
							(*coll_hash)[*coll_amt] = rema | (current_run << qfa->metadata->bits_per_slot) | (exta << (qfa->metadata->quotient_bits + qfa->metadata->bits_per_slot));
							(*coll_len)[*coll_amt] = (extlena * qfa->metadata->bits_per_slot) + qfa->metadata->quotient_bits + qfa->metadata->bits_per_slot;
							if ((++(*coll_amt)) == coll_size) {
								coll_size <<= 1;
								*coll_hash = realloc(*coll_hash, coll_size);
								*coll_len = realloc(*coll_hash, coll_size);
							}
						}
						// TODO: come up with some contingency for when the filters have different numbers of bits per slot?
						qfi_next(&qfia);
						qfi_next(&qfib);
						qfi_get_hash(&qfia, &rema, &exta, &extlena, &counta);
						qfi_get_hash(&qfib, &remb, &extb, &extlenb, &countb);
						break;
					case -1:
						current_index = _merge_insert(qfc, current_index, current_run, rema, exta, extlena, counta);
						qfi_next(&qfia);
						qfi_get_hash(&qfia, &rema, &exta, &extlena, &counta);
						break;
					case 1:
						current_index = _merge_insert(qfc, current_index, current_run, remb, extb, extlenb, countb);
						qfi_next(&qfib);
						qfi_get_hash(&qfib, &remb, &extb, &extlenb, &countb);
						break;
				}
			}
			// if qfa has more items for this run but qfb does not, then add all the items from the run in qfa
			else {
				do {
					last_index = current_index;
					current_index = _merge_insert(qfc, current_index, qfia.run, rema, exta, extlena, counta);
					qfi_next(&qfia);
					qfi_get_hash(&qfia, &rema, &exta, &extlena, &counta);
				} while (qfia.run == current_run);
			}
		}
		else {
			// if qfb has more items for this run but qfa does not, then add all the items from the run in qfb
			if (qfib.run == current_run) {
				do {
					last_index = current_index;
					current_index = _merge_insert(qfc, current_index, qfib.run, remb, extb, extlenb, countb);
					qfi_next(&qfib);
					qfi_get_hash(&qfib, &remb, &extb, &extlenb, &countb);
				} while (qfib.run == current_run);
			}
			else {
				if (qfia.run < qfib.run) current_run = qfia.run;
				else current_run = qfib.run;
				if (current_index < current_run) current_index = current_run;
				METADATA_WORD(qfc, occupieds, current_run) |= (1ULL << (current_run % QF_SLOTS_PER_BLOCK));
				if (last_index != -1) METADATA_WORD(qfc, runends, last_index) |= (1ULL << (last_index % QF_SLOTS_PER_BLOCK));
			}
		}
	} while(!qfi_end(&qfia) && !qfi_end(&qfib));

	if (!qfi_end(&qfia)) {
		do {
			if (qfia.run != current_run) {
				current_run = qfia.run;
				if (current_index < current_run) current_index = current_run;
				METADATA_WORD(qfc, occupieds, current_run) |= (1ULL << (current_run % QF_SLOTS_PER_BLOCK));
				if (last_index != -1) METADATA_WORD(qfc, runends, last_index) |= (1ULL << (last_index % QF_SLOTS_PER_BLOCK));
			}
			last_index = current_index;
			qfi_get_hash(&qfia, &rema, &exta, &extlena, &counta);
			current_index = _merge_insert(qfc, current_index, qfia.run, rema, exta, extlena, counta);
		} while(!qfi_next(&qfia));
	}
	if (!qfi_end(&qfib)) {
		do {
			if (qfib.run != current_run) {
				current_run = qfib.run;
				if (current_index < current_run) current_index = current_run;
				METADATA_WORD(qfc, occupieds, current_run) |= (1ULL << (current_run % QF_SLOTS_PER_BLOCK));
				if (last_index != -1) METADATA_WORD(qfc, runends, last_index) |= (1ULL << (last_index % QF_SLOTS_PER_BLOCK));
			}
			last_index = current_index;
			qfi_get_hash(&qfib, &remb, &extb, &extlenb, &countb);
			current_index = _merge_insert(qfc, current_index, qfib.run, remb, extb, extlenb, countb);
		} while(!qfi_next(&qfib));
	}
	if (last_index != -1) METADATA_WORD(qfc, runends, last_index) |= (1ULL << (last_index % QF_SLOTS_PER_BLOCK));

}

inline int qf_hash_cmp(const QF *qf, const uint64_t hash1, const uint64_t hash2) {
	if (hash1 == hash2) return 0;
	uint64_t temp1 = (hash1 >> qf->metadata->bits_per_slot) & BITMASK(qf->metadata->quotient_bits);
	uint64_t temp2 = (hash2 >> qf->metadata->bits_per_slot) & BITMASK(qf->metadata->quotient_bits);
	if (temp1 == temp2) {
		temp1 = hash1 & BITMASK(qf->metadata->bits_per_slot);
		temp2 = hash2 & BITMASK(qf->metadata->bits_per_slot);
		if (temp1 == temp2) {
			temp1 = hash1 >> qf->metadata->quotient_bits;
			temp2 = hash2 >> qf->metadata->quotient_bits;
			while (temp1 != 0 && temp2 != 0) {
				temp1 >>= qf->metadata->bits_per_slot;
				temp2 >>= qf->metadata->bits_per_slot;
				if ((temp1 & BITMASK(qf->metadata->bits_per_slot)) == (temp2 & BITMASK(qf->metadata->bits_per_slot))) continue;
				if ((temp1 & BITMASK(qf->metadata->bits_per_slot)) > (temp2 & BITMASK(qf->metadata->bits_per_slot))) return 1;
				else return -1;
			}
			if (temp1 == 0) return -1;
			else return 1;
		}
		else if (temp1 > temp2) return 1;
		else return -1;
	}
	else if (temp1 > temp2) return 1;
	else return -1;
}

// sorts the items in a list to prepare for use in qf_bulk_insert
// assumes the items in the list have already been hashed
void bulk_insert_sort_hashes(const QF *qf, uint64_t *keys, int nkeys) {
	uint64_t rem, run, ext;
	int ext_bits = 64 - qf->metadata->quotient_bits - qf->metadata->bits_per_slot;
	for (int i = 0; i < nkeys; i++) {
		rem = keys[i] & BITMASK(qf->metadata->bits_per_slot);
		run = (keys[i] >> qf->metadata->bits_per_slot) & BITMASK(qf->metadata->quotient_bits);
		uint64_t temp_ext = keys[i] >> (qf->metadata->quotient_bits + qf->metadata->bits_per_slot);
		int temp_ext_len = 0;
		ext = 0;
		for (temp_ext_len = 0; temp_ext > 0; temp_ext_len++) {
			ext <<= 1;
			ext |= temp_ext & 1;
			temp_ext >>= 1;
		}
		ext <<= ext_bits - temp_ext_len;
		keys[i] = ext | (rem << ext_bits) | (run << (ext_bits + qf->metadata->bits_per_slot));
	}
}

__attribute__((always_inline))
static inline uint32_t fast_reduce(uint32_t hash, uint32_t n) {
    // http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
    return (uint32_t) (((uint64_t) hash * n) >> 32);
}

uint64_t arqf_hash(QF* qf, uint64_t x)
{
  const uint64_t quotient_bits = qf->metadata->quotient_bits;
  const uint64_t remainder_bits = qf->metadata->key_remainder_bits;
  const uint64_t memento_bits = qf->metadata->value_bits;
  const uint64_t n_slots = qf->metadata->nslots;
  const uint64_t seed = qf->metadata->seed;

  const uint64_t quotient_mask = (1ULL << quotient_bits) - 1;
  const uint64_t memento_mask = (1ULL << memento_bits) - 1;
  const uint64_t hash_mask = (1ULL << (quotient_bits + remainder_bits)) - 1;
  // WARNING: Don't use auto here. For some reason, using auto y, results in sizeof(y)=4
  // TODO(chesetti): Find out why this is the case.
  uint64_t y = x >> memento_bits;
  uint64_t mhash = MurmurHash64A(((void*)&y), sizeof(y), seed);
  // Use the lower order q bits of mhash to determine address.
  const uint64_t address = fast_reduce((mhash & quotient_mask) << (32 - quotient_bits),
      n_slots);
  // Use the lower order r (after q bits) of mhash to determine reminder.
  uint64_t hash = ((mhash & hash_mask) >> quotient_bits) | (address << remainder_bits);
  hash = (hash << memento_bits) | (x & memento_mask);
  // Fill the higher order bits with bits from the MurmurHash, these will be used as extensions.
  hash = hash | (mhash & ~BITMASK(quotient_bits + remainder_bits + memento_bits));
  return hash;
}



/*
 * Copy the [0..buffer_offset) bits in buffer to the quotient filter, starting from slot_index.
 * The final slot might not be fully used, in which case those bits will be set to 0.
 * This method will handle the case of slots going across blocks and uses set_slot method under the hood.
 * The metadata bits are NOT handled in this method.
 */
static inline void _keepsake_flush_mementos(
    QF* qf,
    uint64_t* slot_index,
    uint64_t* buffer,
    uint64_t* buffer_offset)
{
  // NICE_TO_HAVE(chesetti): Optimize flush_mementos.
  // The flush basically writes out one slot at a time, I'm sure we could
  // optimize it further with memcpy, but that will require needing to handle
  // the case where slots go across blocks.
  uint64_t bits_per_slot = qf->metadata->bits_per_slot;
  *buffer = *buffer & BITMASK(*buffer_offset);
  while (*buffer_offset >= bits_per_slot) {
    set_slot(qf, (*slot_index), (*buffer) & BITMASK(qf->metadata->bits_per_slot));
    *slot_index = *slot_index+1;
    *buffer_offset = (*buffer_offset - bits_per_slot);
    *buffer = (*buffer >> bits_per_slot);
  }
  if (*buffer_offset > 0) {
    set_slot(qf, *slot_index, (*buffer) & BITMASK(*buffer_offset));
    *slot_index = *slot_index+1;
  }
  *buffer = 0;
  *buffer_offset = 0;
}

static inline void _keepsake_add_remainder(
    QF* qf,
    const uint64_t keepsake,
    uint64_t* buffer,
    uint64_t* buffer_offset)
{
  assert(*buffer == 0);
  assert(*buffer_offset == 0);
  *buffer = *buffer | keepsake & BITMASK(qf->metadata->key_remainder_bits);
  *buffer_offset = *buffer_offset + qf->metadata->key_remainder_bits;
}

/* Add the memento to a buffer, flushing to QF if the buffer overflows. 
 * Meant to be used as helper method for bulk_load.
 * The combintation of (current_slot, buffer, buffer_offset) can be interpreted as 
 * internals of a builder interface.
 * */
static inline void _keepsake_add_memento(
    QF* qf,
    uint64_t memento,
    uint64_t* current_slot, /* memento index in keepsake run */
    uint64_t* buffer,
    uint64_t* buffer_offset)
{
  uint64_t bits_per_slot = qf->metadata->bits_per_slot;
  uint64_t bits_per_memento = qf->metadata->value_bits;
  uint64_t slots_per_buffer = (sizeof(uint64_t) * 8) / bits_per_slot;
  uint64_t slots_used = (*buffer_offset) / bits_per_slot;
  memento = memento & BITMASK(bits_per_memento);
  if (*buffer_offset + bits_per_memento <= slots_per_buffer * bits_per_slot) {
    // Not exceeding the slots, just add the bits and be done.
    *buffer = *buffer | (memento << *buffer_offset);
    *buffer_offset = *buffer_offset + bits_per_memento;
  } else {
    int bits_left_in_last_slot = (slots_per_buffer * bits_per_slot) - (*buffer_offset);
    // copy the bits.
    *buffer = *buffer | ((memento & BITMASK(bits_left_in_last_slot)) << *buffer_offset);
    *buffer_offset = *buffer_offset + bits_left_in_last_slot;
    // flush.
    _keepsake_flush_mementos(qf, current_slot, buffer, buffer_offset);
    // copy the leftover bits
    *buffer = *buffer | (memento >> bits_left_in_last_slot);
    *buffer_offset = *buffer_offset + (bits_per_memento - bits_left_in_last_slot);
  }
}

// assumes keys are provided in sorted order of (fingerprint, memento).
// Does NOT insert extensions for keys that have the same fingerprint.
// The sorted hash is assumed to store memento_bits in lower memento_bits,
// followed by fingerprints in the next higher bits.
// 000..FM (F=Fingerprint bits, M=memento bits).
// All bits after the (fingerprint+memento) lower bits are ignored.
int qf_bulk_load(QF* qf, uint64_t* sorted_hashes, uint64_t nkeys)
{
  // memento is the suffix of the key.
  // keepsake is the fingerprint remainders of the partition of the key.
  uint64_t current_quotient = 0, current_run_start_slot = 0, current_run = 0, current_keepsake_remainder = 0, current_memento = 0;
  uint64_t next_quotient = 0, next_keepsake_remainder = 0, next_memento = 0;
  uint64_t slot_buffer = 0, slot_buffer_offset = 0, slot_buffer_index = 0;
  if (nkeys > 0) {
    current_quotient = (sorted_hashes[0] >> qf->metadata->bits_per_slot) & BITMASK(qf->metadata->quotient_bits);
    current_run_start_slot = current_quotient;
    slot_buffer_index = current_run_start_slot;
    current_keepsake_remainder = (sorted_hashes[0] >> qf->metadata->value_bits) & BITMASK(qf->metadata->key_remainder_bits);
    current_memento = (sorted_hashes[0]) & BITMASK(qf->metadata->value_bits);
    _keepsake_add_remainder(qf, current_keepsake_remainder, &slot_buffer, &slot_buffer_offset);
    METADATA_WORD(qf, occupieds, current_quotient) |= (1ULL << ((current_quotient) % QF_SLOTS_PER_BLOCK));
  }

  int skip_memento = 0;
  for (uint64_t i = 1; i < nkeys; i++) {
    if (slot_buffer_index > qf->metadata->xnslots) {
      return QF_INVALID;
    }
    if (!skip_memento) {
      _keepsake_add_memento(qf, current_memento, &slot_buffer_index, &slot_buffer, &slot_buffer_offset);
    }
    if (sorted_hashes[i] < sorted_hashes[i - 1]) {
      return QF_INVALID;
    }
    next_quotient = (sorted_hashes[i] >> qf->metadata->bits_per_slot) & BITMASK(qf->metadata->quotient_bits);
    next_keepsake_remainder = (sorted_hashes[i] >> qf->metadata->value_bits) & BITMASK(qf->metadata->key_remainder_bits);
    next_memento = (sorted_hashes[i]) & BITMASK(qf->metadata->value_bits);
    skip_memento = 0;

    // Don't add the same fingerprint twice.
    if (next_quotient == current_quotient && next_keepsake_remainder == current_keepsake_remainder && next_memento == current_memento) {
      skip_memento = 1;
      continue;
    }

    if (next_quotient == current_quotient && next_keepsake_remainder != current_keepsake_remainder) {
      _keepsake_flush_mementos(qf, &slot_buffer_index, &slot_buffer, &slot_buffer_offset);
      // Mark end of keepsake run.
      METADATA_WORD(qf, runends, slot_buffer_index - 1) |= (1ULL << ((slot_buffer_index - 1) % QF_SLOTS_PER_BLOCK));
      METADATA_WORD(qf, extensions, slot_buffer_index - 1) |= (1ULL << ((slot_buffer_index - 1) % QF_SLOTS_PER_BLOCK));
      // Start new keepsake.
      _keepsake_add_remainder(qf, next_keepsake_remainder, &slot_buffer, &slot_buffer_offset);
    } else if (next_quotient != current_quotient) {
      _keepsake_flush_mementos(qf, &slot_buffer_index, &slot_buffer, &slot_buffer_offset);
      // Mark runend of this quotient run.
      METADATA_WORD(qf, runends, slot_buffer_index - 1) |= (1ULL << ((slot_buffer_index - 1) % QF_SLOTS_PER_BLOCK));
      uint64_t cur_block = (current_quotient + QF_SLOTS_PER_BLOCK) / QF_SLOTS_PER_BLOCK;
      uint64_t offset = (slot_buffer_index) - (cur_block * QF_SLOTS_PER_BLOCK);
      while (cur_block * QF_SLOTS_PER_BLOCK <= next_quotient) {
        offset = (slot_buffer_index) - (cur_block * QF_SLOTS_PER_BLOCK);
        if (offset < BITMASK(8 * sizeof(qf->blocks[0].offset))) {
          get_block(qf, cur_block)->offset = (uint8_t)offset;
        } else {
          get_block(qf, cur_block)->offset = (uint8_t)BITMASK(8 * sizeof(qf->blocks[0].offset));
        }
        cur_block++;
      }
      current_quotient = (sorted_hashes[i] >> qf->metadata->bits_per_slot) & (BITMASK(qf->metadata->quotient_bits));
      if (slot_buffer_index < current_quotient)
        slot_buffer_index = current_quotient;
      current_run_start_slot = slot_buffer_index;
      // Start new keepsake and quotient run.
      METADATA_WORD(qf, occupieds, current_quotient) |= (1ULL << ((current_quotient) % QF_SLOTS_PER_BLOCK));
      _keepsake_add_remainder(qf, next_keepsake_remainder, &slot_buffer, &slot_buffer_offset);
    }
    current_quotient = next_quotient;
    current_keepsake_remainder = next_keepsake_remainder;
    current_memento = next_memento;
  }
  _keepsake_add_memento(qf, current_memento, &slot_buffer_index, &slot_buffer, &slot_buffer_offset);
  _keepsake_flush_mementos(qf, &slot_buffer_index, &slot_buffer, &slot_buffer_offset);
  METADATA_WORD(qf, runends, slot_buffer_index-1) |= (1ULL << ((slot_buffer_index-1) % QF_SLOTS_PER_BLOCK));
  uint64_t cur_block = (current_run_start_slot + QF_SLOTS_PER_BLOCK) / QF_SLOTS_PER_BLOCK;
  while (cur_block * QF_SLOTS_PER_BLOCK <= slot_buffer_index) {
    uint64_t offset = (slot_buffer_index) - (cur_block * QF_SLOTS_PER_BLOCK);
    if (offset < BITMASK(8 * sizeof(qf->blocks[0].offset))) {
      get_block(qf, cur_block)->offset = offset;
    } else {
      get_block(qf, cur_block)->offset = BITMASK(8 * sizeof(qf->blocks[0].offset));
    }
    cur_block++;
  }
  return 0;
}

static inline uint64_t lower_bound_remainder(const QF *qf, const uint64_t remainder, uint64_t *current_idx) {
  uint64_t current_remainder = GET_REMAINDER(qf, *current_idx); 
  while (current_remainder < remainder) {
    if (is_keepsake_or_quotient_runend(qf, *current_idx)) {
      // If the current idx is the end of this keepsake box (contains only one item),
      // increment and continue.
      (*current_idx)++;
    }
    else {
      // Use bitselectv to find next runend.
      uint64_t current_block = ((*current_idx) / QF_SLOTS_PER_BLOCK);
      uint64_t next_runend_offset = bitselectv(get_block(qf, current_block)->runends[0], *current_idx, 0);
      while (next_runend_offset == 64) {
        current_block++;
	      next_runend_offset = bitselectv(get_block(qf, current_block)->runends[0], 0, 0);
      }
      *current_idx = current_block * QF_SLOTS_PER_BLOCK + next_runend_offset + 1; 
    }

    if (is_runend(qf, *current_idx-1)) {
      return current_remainder;
    }
    current_remainder = GET_REMAINDER(qf, *current_idx);
  }
  // current_idx should be set to first remainder >= remainder, or after the runend.
  // current_remainder will be set to first remainder >= remainder or the last remainder.
  return current_remainder;
}


static inline uint64_t lower_bound_memento(const QF *qf, const uint64_t memento, const uint64_t runstart_index, uint64_t memento_offset) {
  // Here runstart_index is start of keepsake box.
  uint64_t current_idx = runstart_index;
  uint64_t current_slot = get_slot(qf, current_idx);
  current_slot = current_slot >> memento_offset;
  uint64_t current_memento = current_slot & BITMASK(qf->metadata->value_bits);;
  uint64_t next_memento;

  while (current_memento < memento) {
    memento_offset += qf->metadata->value_bits;
    if (memento_offset >= qf->metadata->bits_per_slot) {
      if (is_keepsake_or_quotient_runend(qf, current_idx)) 
        break;
      memento_offset -= qf->metadata->bits_per_slot;
      current_idx++;
      current_slot = get_slot(qf, current_idx);
      current_slot >>= memento_offset;
    }

    if (memento_offset + qf->metadata->value_bits > qf->metadata->bits_per_slot) {
      if (is_keepsake_or_quotient_runend(qf, current_idx)) return current_memento;
      const uint64_t bits_from_cur_slot = qf->metadata->bits_per_slot - memento_offset;
      const uint64_t bits_from_next_slot = qf->metadata->value_bits - bits_from_cur_slot;
      next_memento = current_slot | ((get_slot(qf, current_idx+1) & BITMASK(bits_from_next_slot)) << bits_from_cur_slot);
    } else {
      next_memento = (current_slot) & BITMASK(qf->metadata->value_bits);
      current_slot >>= qf->metadata->value_bits;
    }
    if (next_memento < current_memento) break;
    current_memento = next_memento;
  }
  return current_memento;
}

static inline uint64_t read_extension_bits(const QF* qf, uint64_t extension_index, uint64_t *num_ext_bits)
{
  int extension_offset = 0;
  *num_ext_bits = 0;
  uint64_t cur_qf_extension = 0;
  if (is_extension(qf, extension_index)) {
    cur_qf_extension = GET_FIRST_EXTENSION(qf, extension_index);
    extension_index++;
    extension_offset += qf->metadata->value_bits;
    *num_ext_bits += qf->metadata->value_bits;
  }
  while (is_extension(qf, extension_index)) {
    cur_qf_extension |= (get_slot(qf, extension_index) << extension_offset);
    extension_index++;
    *num_ext_bits += qf->metadata->bits_per_slot;
    extension_offset += qf->metadata->bits_per_slot;
  }
  return cur_qf_extension;
}

int find_colliding_fingerprint(
    const QF* qf,
    uint64_t fp_hash,
    uint64_t* colliding_fingerprint,
    uint64_t* start_index,
    uint64_t* num_ext_bits,
    uint64_t* keepsake_runend_index)
{
  // Remove the memento bits.
  fp_hash >>= qf->metadata->value_bits;

  const uint64_t quotient_bits = qf->metadata->quotient_bits;
  const uint64_t remainder_bits = qf->metadata->key_remainder_bits;
  const uint64_t memento_bits = qf->metadata->value_bits;
  const uint64_t fp_remainder = (fp_hash)&BITMASK(remainder_bits);
  const uint64_t fp_quotient = (fp_hash >> (remainder_bits)) & BITMASK(quotient_bits);
  const uint64_t fp_ext_bits = (fp_hash >> (quotient_bits + remainder_bits));

  if (!is_occupied(qf, fp_quotient)) {
    *num_ext_bits = -1; // Quoitent/Remainder does not exist.
    return -1;
  }
  *start_index = fp_quotient == 0 ? 0 : run_end(qf, fp_quotient - 1) + 1;
  if (*start_index < fp_quotient)
    *start_index = fp_quotient;
  uint64_t colliding_remainder = lower_bound_remainder(qf, fp_remainder, start_index);
  if (colliding_remainder != fp_remainder) {
    *colliding_fingerprint = colliding_remainder;
    *num_ext_bits = -1; // Quoitent/Remainder does not exist.
    return -1;
  }
  const uint64_t keepsake_start = *start_index; // Needed if fingerprint does not exist, but remainder does.

  uint64_t min_ext_bits = 0; // If fp_hash was to be inserted, what is the minimum extension bits needed.
  uint64_t cur_qf_extension = 0;
  do {
    cur_qf_extension = read_extension_bits(qf, *start_index, num_ext_bits);
    if (cur_qf_extension == (fp_ext_bits & BITMASK(*num_ext_bits))) {
      break;
    }

    assert(num_ext_bits > 0); // If num_ext_bits != 0 remainder should have matched.
    uint64_t diff_ext_bits = qf->metadata->value_bits;
    while ((cur_qf_extension & BITMASK(diff_ext_bits)) == (fp_ext_bits & BITMASK(diff_ext_bits))) {
      diff_ext_bits += qf->metadata->bits_per_slot;
    }
    if (min_ext_bits > diff_ext_bits) min_ext_bits = diff_ext_bits;

    uint64_t current_block = ((*start_index) / QF_SLOTS_PER_BLOCK);
    uint64_t next_runend_offset = bitselectv(get_block(qf, current_block)->runends[0], *start_index, 0);
    while (next_runend_offset == 64) {
      current_block++;
      next_runend_offset = bitselectv(get_block(qf, current_block)->runends[0], 0, 0);
    }
    *start_index = current_block * QF_SLOTS_PER_BLOCK + next_runend_offset;
    (*start_index)++;
    // You cannot check for is_keepsake_or_quotient runend here.
    // *start_index - 1 will always be a runend. We just need to check if we 
    // have come out of the remainder.
    if (is_runend(qf, *start_index - 1) || GET_REMAINDER(qf, *start_index) != fp_remainder) {
      *keepsake_runend_index = (*start_index - 1);
      *start_index = keepsake_start;
      *num_ext_bits = min_ext_bits; // If fp_hash was going to be inserted, you need atleast these many extension bits.
      return -1;
    }
  } while (true);

  const uint64_t colliding_extension_bits = cur_qf_extension;
  *colliding_fingerprint = fp_hash & BITMASK(quotient_bits + remainder_bits);
  *colliding_fingerprint |= (colliding_extension_bits << (quotient_bits + remainder_bits));
#if DEBUG
   // fprintf(stderr, "%016llx hash collided with fingerprint %016llx \n", fp_hash, *colliding_fingerprint);
#endif
  *keepsake_runend_index = *start_index;
  uint64_t current_block = ((*keepsake_runend_index) / QF_SLOTS_PER_BLOCK);
  uint64_t next_runend_offset = bitselectv(get_block(qf, current_block)->runends[0], *keepsake_runend_index, 0);
  while (next_runend_offset == 64) {
    current_block++;
    next_runend_offset = bitselectv(get_block(qf, current_block)->runends[0], 0, 0);
  }
  *keepsake_runend_index = current_block * QF_SLOTS_PER_BLOCK + next_runend_offset;
  return 0;
}

// Insert lower_order num_bits from value, starting at (slot) + slot_offset bit.
// Anything after last_written_slot and old_runend can be rewritten.
// If you need more space, then shift using insert_one_slot.
static inline int _add_to_end_of_keepsake_run(
    QF* qf,
    uint64_t quotient,
    uint64_t value,
    uint64_t slot,
    int slot_offset,
    int num_bits,
    int is_new_keepsake,
    uint64_t* last_written_slot,
    uint64_t* keepsake_runend)
{
#if DEBUG
  int keepsake_runend_is_quotient_runend = 0;
  if (is_runend(qf, *keepsake_runend)) {
    keepsake_runend_is_quotient_runend = 1;
  }
#endif

  int num_available_slots = (*keepsake_runend - *last_written_slot);
  if (num_available_slots < 0)
    num_available_slots = 0;

  int num_slots_consumed = 0;
  while (num_bits) {
    // First lets make space if needed.
    if (slot_offset == 0) {
      if (num_available_slots > 0) {
        if (slot <= *last_written_slot) {
          // Inserting in middle of overwritten run.
          shift_remainders(qf, slot, *last_written_slot + 1);
          shift_runends(qf, slot, *last_written_slot, 1);
        }
        (*last_written_slot)++;
        num_available_slots--;
      } else {
        if (slot == (*keepsake_runend) + 1) {
          // This should preserve the runend bits of keepsake_runend.
          // We need valid runends so that that insert_one_slot works as intented.
          insert_one_slot(qf, quotient, slot - 1, 0);
          uint64_t last_slot_value = get_slot(qf, slot);
          set_slot(qf, slot - 1, last_slot_value);
          set_slot(qf, slot, 0);
          if (is_new_keepsake & num_slots_consumed == 0) {
            // If we are starting a new keepsake and this is its first slot, 
            // we need to mark the previous slot as a keepsake end.
            METADATA_WORD(qf, extensions, slot-1) |= (1ULL << ((slot-1) % QF_SLOTS_PER_BLOCK));
            METADATA_WORD(qf, runends, slot-1) |= (1ULL << ((slot-1) % QF_SLOTS_PER_BLOCK));
          }
        } else {
          insert_one_slot(qf, quotient, slot, 0);
        }
        (*keepsake_runend)++;
        (*last_written_slot)++;
      }
    }
    // We've made space, so now just write out as many bits possible.
    uint64_t slot_value = get_slot(qf, slot);
    slot_value = slot_value & BITMASK(slot_offset);
    int space_in_cur_slot = (qf->metadata->bits_per_slot - slot_offset);
    if (space_in_cur_slot > num_bits) {
      space_in_cur_slot = num_bits;
    }
    slot_value |= ((value & BITMASK(space_in_cur_slot)) << slot_offset);
    set_slot(qf, slot, slot_value);

    if (slot != *keepsake_runend) {
      METADATA_WORD(qf, extensions, slot) &= ~(1ULL << (slot % QF_SLOTS_PER_BLOCK));
      METADATA_WORD(qf, runends, slot) &= ~(1ULL << (slot % QF_SLOTS_PER_BLOCK));
    }
    value = value >> space_in_cur_slot;
    num_bits -= space_in_cur_slot;
    slot_offset = 0;
    slot++;
    num_slots_consumed++;
  }
  uint64_t last_slot = slot - 1;
  if (last_slot != *keepsake_runend) {
    METADATA_WORD(qf, extensions, last_slot) |= (1ULL << (last_slot % QF_SLOTS_PER_BLOCK));
    METADATA_WORD(qf, runends, last_slot) |= (1ULL << (last_slot % QF_SLOTS_PER_BLOCK));
  }
#if DEBUG
  assert(is_keepsake_or_quotient_runend(qf, *keepsake_runend));
  if(keepsake_runend_is_quotient_runend) {
    assert(is_runend(qf, *keepsake_runend));
  }
#endif
  return 0;
}

int _overwrite_keepsake(QF* qf, uint64_t fingerprint, uint8_t num_fingerprint_bits, uint64_t memento, uint64_t start_index, uint64_t* last_overwritten_index, uint64_t* old_keespake_runend)
{
  // assert(num_fingerprint_bits >= qf->metadata->quotient_bits + qf->metadata->bits_per_slot);
#if DEBUG
  uint64_t hash = fingerprint;
#endif
  int verbose = 0;
  int extension_found = 0;
  uint64_t current_index = start_index;
  uint64_t fingerprint_remainder = fingerprint & BITMASK(qf->metadata->key_remainder_bits);
  uint8_t num_ext_bits = num_fingerprint_bits;
  // ASSUMES REMAINDER EXISTS AT START_INDEX
  assert(GET_REMAINDER(qf, current_index) == fingerprint_remainder);
  fingerprint >>= qf->metadata->key_remainder_bits;
  num_ext_bits -= qf->metadata->key_remainder_bits;

  uint64_t fingerprint_quotient = fingerprint & BITMASK(qf->metadata->quotient_bits);
  fingerprint >>= qf->metadata->quotient_bits;
  num_ext_bits -= qf->metadata->quotient_bits;
  uint64_t fingerprint_ext_bits = fingerprint & BITMASK(num_ext_bits);

  while (current_index <= *last_overwritten_index) {
    uint64_t num_ext_bits_from_slot;
    uint64_t cur_qf_extension = read_extension_bits(qf, current_index, &num_ext_bits_from_slot);
    if (cur_qf_extension == fingerprint_ext_bits) {
      assert(num_ext_bits == num_ext_bits_from_slot);
      extension_found = 1;
      break;
    }
    if (cur_qf_extension > fingerprint_ext_bits) {
      break;
    }
    // Go to next extension index
    while (!is_keepsake_or_quotient_runend(qf, current_index)) {
      current_index++;
    }
    current_index++;
  }

  if (!extension_found) {
#if DEBUG
    fprintf(stdout, "Inserting extenstion at %lld\n", current_index);
#endif
    uint64_t value = fingerprint_remainder;
    value |= (fingerprint_ext_bits << qf->metadata->key_remainder_bits);
    value |= (memento << (num_ext_bits + qf->metadata->key_remainder_bits));
    int num_bits = num_ext_bits + qf->metadata->bits_per_slot; // bits_per_slot = remainder + memento.
    if (num_bits > 64) {
      perror("Too many extensions\n");
      abort(); // TODO(chesetti): TOO MANY EXTENSIONS!
    }
    _add_to_end_of_keepsake_run(
        qf, 
        fingerprint_quotient, 
        value, 
        current_index, 
        0 /*slot_offset*/, 
        num_bits, 
        1, /*new keepsake*/
        last_overwritten_index, 
        old_keespake_runend
      );
#if DEBUG
    fprintf(stdout, "Should have inserted %llu (with extension) at %lld\n", value, current_index);
#endif
    if (num_ext_bits) {
      num_ext_bits -= qf->metadata->value_bits;
      METADATA_WORD(qf, extensions, current_index) |= (1ULL << (current_index % QF_SLOTS_PER_BLOCK));
      while (num_ext_bits) {
        current_index++;
        METADATA_WORD(qf, extensions, current_index) |= (1ULL << (current_index % QF_SLOTS_PER_BLOCK));
        num_ext_bits -= qf->metadata->bits_per_slot;
      }
    }
#if DEBUG
    if(qf_point_query(qf, (hash << qf->metadata->value_bits) | memento, QF_KEY_IS_HASH)==0) {
      printf("Not found, something is wrong!\n");
      // This is to let gdb inspect the query.
      int result = qf_point_query(qf, (hash << qf->metadata->value_bits) | memento, QF_KEY_IS_HASH);
      printf("%d\n", result);
    }
#endif
    return 0;
  }

  // Extension exists. Walk through all mementos and insert in order.
  uint64_t memento_offset;
  if (num_ext_bits) {
    num_ext_bits -= qf->metadata->value_bits;
    current_index++;
    while (num_ext_bits) {
      current_index++;
      num_fingerprint_bits -= qf->metadata->bits_per_slot;
    }
    memento_offset = 0; // extension end always aligns with slots.
  } else {
    memento_offset = qf->metadata->key_remainder_bits;
  }

  uint64_t current_slot = get_slot(qf, current_index) >> memento_offset;
  uint64_t current_memento = current_slot & BITMASK(qf->metadata->value_bits);
  while (true) {
    if (memento_offset + qf->metadata->value_bits > qf->metadata->bits_per_slot) {
      if (is_keepsake_or_quotient_runend(qf, current_index)) {
        break;
      };
      const uint64_t bits_from_cur_slot = qf->metadata->bits_per_slot - memento_offset;
      const uint64_t bits_from_next_slot = qf->metadata->value_bits - bits_from_cur_slot;
      uint64_t next_memento = current_slot | ((get_slot(qf, current_index + 1) & BITMASK(bits_from_next_slot)) << bits_from_cur_slot);
      if (next_memento > memento) {
        uint64_t cur_slot_value = get_slot(qf, current_index);
        cur_slot_value &= BITMASK(memento_offset);
        cur_slot_value |= ((memento & BITMASK(bits_from_cur_slot)) << memento_offset);
        set_slot(qf, current_index, cur_slot_value);

        cur_slot_value = get_slot(qf, current_index + 1);
        cur_slot_value &= ~BITMASK(bits_from_next_slot);
        cur_slot_value |= ((memento >> bits_from_cur_slot) & BITMASK(bits_from_next_slot));
        set_slot(qf, current_index + 1, cur_slot_value);

        current_memento = memento;
        memento = next_memento;
      } else {
        current_memento = next_memento;
      }
    } else {
      uint64_t next_memento = (current_slot)&BITMASK(qf->metadata->value_bits);
      current_slot >>= qf->metadata->value_bits;
      if (current_memento > next_memento) {
        // Relying on mementos to be unique for this condition to be correct even if first memento is 0.
        break;
      }
      if (next_memento > memento) {
        // We need to rewrite this slot.
        uint64_t slot_value = get_slot(qf, current_index);
        uint64_t mask = ~(BITMASK(qf->metadata->value_bits) << memento_offset);
        slot_value &= mask;
        slot_value |= (memento << memento_offset);
        set_slot(qf, current_index, slot_value);
        current_memento = memento;
        memento = next_memento;
      } else {
        current_memento = next_memento;
      }
    }
    memento_offset += qf->metadata->value_bits;
    if (memento_offset >= qf->metadata->bits_per_slot) {
      if (is_keepsake_or_quotient_runend(qf, current_index)) {
        // This case should only happen when memento_offset == qf->metadata->bits_per_slot.
        // If it is greater, then we already read across slots, so current_idx cannot be runend.
        assert(memento_offset == qf->metadata->bits_per_slot);
        break;
      }
      memento_offset -= qf->metadata->bits_per_slot;
      current_index++;
      current_slot = get_slot(qf, current_index);
      current_slot >>= memento_offset;
    }
  }
#if DEBUG
    fprintf(stdout, "Should have inseerted %llu (with extension) at %lld %lld\n", memento, current_index, memento_offset);
#endif
  _add_to_end_of_keepsake_run(
      qf, 
      fingerprint_quotient, 
      memento, 
      current_index, 
      memento_offset, 
      qf->metadata->value_bits, 
      0, /* new keepsake */
      last_overwritten_index, 
      old_keespake_runend
    );
  return 0;
}

int qf_point_query(const QF* qf, uint64_t key, uint8_t flags) {
  uint64_t hash = key;
  if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
    hash = arqf_hash(qf, key);
  }
  const uint64_t hash_memento = hash & BITMASK(qf->metadata->value_bits);
  const uint64_t hash_remainder = (hash >> qf->metadata->value_bits) & BITMASK(qf->metadata->key_remainder_bits);
  const uint64_t hash_quotient = (hash >> (qf->metadata->key_remainder_bits + qf->metadata->value_bits)) & BITMASK(qf->metadata->quotient_bits);
  const uint64_t hash_ext_bits = (hash >> (qf->metadata->quotient_bits + qf->metadata->bits_per_slot));

  if (!is_occupied(qf, hash_quotient)) {
    return 0;
  }
  uint64_t colliding_fingerprint, current_index, num_ext_bits, runend_index; 
  int ret = find_colliding_fingerprint(qf, hash, &colliding_fingerprint, &current_index, &num_ext_bits, &runend_index);
  if (ret == -1) {
    return 0; // not found.
  }

  uint64_t memento_offset = qf->metadata->key_remainder_bits;
  if (num_ext_bits) {
    memento_offset = 0;
    num_ext_bits -= qf->metadata->value_bits;
    current_index++;
    while (num_ext_bits) {
      num_ext_bits -= qf->metadata->bits_per_slot;
      current_index++;
    }
  }

  uint64_t nearest_memento = lower_bound_memento(qf, hash_memento, current_index, memento_offset); 
  if (nearest_memento == hash_memento) 
    return 1;
  else 
    return 0;
}

int qf_range_query(const QF* qf, uint64_t l_key, uint64_t r_key, uint8_t flags) {
  uint64_t l_hash = l_key;
  uint64_t r_hash = r_key;
  if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
    abort(); 
  }
  const uint64_t l_remainder = (l_hash >> qf->metadata->value_bits) & BITMASK(qf->metadata->key_remainder_bits);
  const uint64_t l_quotient = (l_hash >> (qf->metadata->key_remainder_bits + qf->metadata->value_bits)) & BITMASK(qf->metadata->quotient_bits);
  const uint64_t l_memento = l_hash & BITMASK(qf->metadata->value_bits);
  const uint64_t r_remainder = (r_hash >> qf->metadata->value_bits) & BITMASK(qf->metadata->key_remainder_bits);
  const uint64_t r_quotient = (r_hash >> (qf->metadata->key_remainder_bits + qf->metadata->value_bits)) & BITMASK(qf->metadata->quotient_bits);
  const uint64_t r_memento = r_hash & BITMASK(qf->metadata->value_bits);

  if (is_occupied(qf, l_quotient)) {
    uint64_t colliding_fingerprint, current_index, num_ext_bits, runend_index; 
    int ret = find_colliding_fingerprint(qf, l_hash, &colliding_fingerprint, &current_index, &num_ext_bits, &runend_index);
    if (ret == 0) {
      uint64_t memento_offset = qf->metadata->key_remainder_bits;
      if (num_ext_bits) {
        memento_offset = 0;
        num_ext_bits -= qf->metadata->value_bits;
        current_index++;
        while (num_ext_bits) {
          num_ext_bits -= qf->metadata->bits_per_slot;
          current_index++;
        }
      }
      uint64_t nearest_memento = lower_bound_memento(qf, l_memento, current_index, memento_offset);
      if (l_remainder == r_remainder && l_quotient == r_quotient) {
        // We can exit early if both the hashes belong to the same keepsake box.
        if (nearest_memento >= l_memento && nearest_memento <= r_memento) {
          return 1;
        }
        else
          return 0;
      } else if (nearest_memento >= l_memento) {
        return 1;
      }
    } else {
      if (l_quotient == r_quotient && l_remainder == r_remainder) {
        // We can exit early if both the hashes belong to the same keepsake box.
        return 0;
      }
    }
  }

  if (is_occupied(qf, r_quotient)) {
    uint64_t colliding_fingerprint, current_index, num_ext_bits, runend_index; 
    int ret = find_colliding_fingerprint(qf, r_hash, &colliding_fingerprint, &current_index, &num_ext_bits, &runend_index);
    if (ret == 0) {
      uint64_t memento_offset = qf->metadata->key_remainder_bits;
      if (num_ext_bits) {
        memento_offset = 0;
        num_ext_bits -= qf->metadata->value_bits;
        current_index++;
        while (num_ext_bits) {
          num_ext_bits -= qf->metadata->bits_per_slot;
          current_index++;
        }
      }
      uint64_t nearest_memento = (get_slot(qf, current_index) >> memento_offset) & BITMASK(qf->metadata->value_bits);
      if (nearest_memento <= r_memento) {
        return 1;
      }
      else return 0;
    }
  }
  return 0;
}

int qf_insert_memento(QF *qf, uint64_t key, uint8_t flags) {
  // TODO(chesetti): Handle case of extensions.
  uint64_t hash = key;
  if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
    abort(); 
  }
  uint64_t hash_memento = hash & BITMASK(qf->metadata->value_bits);
  const uint64_t hash_remainder = (hash >> qf->metadata->value_bits) & BITMASK(qf->metadata->key_remainder_bits);
  const uint64_t hash_quotient = (hash >> (qf->metadata->key_remainder_bits + qf->metadata->value_bits)) & BITMASK(qf->metadata->quotient_bits);
  const uint64_t fingerprint_bits = key >> qf->metadata->value_bits;
  uint64_t runstart_index = hash_quotient == 0 ? 0 : run_end(qf, hash_quotient-1) + 1;
  if (runstart_index < hash_quotient) runstart_index = hash_quotient;
  uint64_t runend_index = run_end(qf, hash_quotient);

  if (!is_occupied(qf, hash_quotient) && runstart_index == hash_quotient) {
    uint64_t slot_value = hash_remainder | (hash_memento << qf->metadata->key_remainder_bits);
    METADATA_WORD(qf, occupieds, hash_quotient) |= (1ULL << (hash_quotient % QF_SLOTS_PER_BLOCK));
    METADATA_WORD(qf, runends, hash_quotient) |= (1ULL << (hash_quotient % QF_SLOTS_PER_BLOCK));
    set_slot(qf, hash_quotient, slot_value);
    assert(run_end(qf, hash_quotient) == runend_index);
    return 0;
  }

  if (!is_occupied(qf, hash_quotient) && runstart_index > hash_quotient) {
    // Empty slot (not occupied), but part of some other run);
    // We need to insert at runend_index+1 now.
    // We also need to free up a slot.
    // printf(" Inserting a new quotient in between at %lld for : %lld\n", runend_index+1, hash_quotient);
    // Insert at runend_index+1;
    uint64_t slot_value = hash_remainder | (hash_memento << qf->metadata->key_remainder_bits);
    insert_one_slot(qf, hash_quotient, runend_index+1, slot_value);
    METADATA_WORD(qf, occupieds, hash_quotient) |= (1ULL << (hash_quotient % 64));
    METADATA_WORD(qf, runends, runend_index+1) |= (1ULL << ((runend_index + 1) % 64));
    assert(run_end(qf, hash_quotient) == runend_index+1);
    return 0;
  }

  
  // It's occupied, so insert the new memento in the existing run.
  // First check if the remainder exists.
  // If it does, iterate over mementos of that remainder.
  //  Keep swapping mementos out, and check if you have space for a new memento.
  // If it doesn't insert a new slot.
  uint64_t target_index = hash_quotient == 0 ? 0 : run_end(qf, hash_quotient-1) + 1;
  if (target_index < hash_quotient) target_index = hash_quotient;

  uint64_t colliding_fingerprint;
  uint64_t num_ext_bits = 0;
  uint64_t keepsake_runend_index;
  int ret = find_colliding_fingerprint(qf, hash, &colliding_fingerprint, &target_index, &num_ext_bits, &keepsake_runend_index);
  uint64_t limit_index = keepsake_runend_index;
  if (ret == 0) { 
    // Keepsake exists. num_ext_bits, runend_index will be set to keepsake
      uint64_t old_memento = (get_slot(qf, target_index) >> qf->metadata->key_remainder_bits);
      uint64_t old_remainder = (get_slot(qf, target_index) & BITMASK(qf->metadata->key_remainder_bits));
    uint64_t num_fingerprint_bits = qf->metadata->quotient_bits + qf->metadata->key_remainder_bits + num_ext_bits;
    _overwrite_keepsake(qf, fingerprint_bits, num_fingerprint_bits, hash_memento, target_index, &limit_index, &keepsake_runend_index);

  } else if (num_ext_bits != -1) {
    // The exact keepsake does not exist, but the remainder exists.
    // So add the new keepsake.
    uint64_t num_fingerprint_bits = qf->metadata->quotient_bits + qf->metadata->key_remainder_bits + num_ext_bits;
    _overwrite_keepsake(qf, fingerprint_bits, num_fingerprint_bits, hash_memento, target_index, &limit_index, &keepsake_runend_index);
  } else if (colliding_fingerprint > hash_remainder) {
      // printf("Remainder does not exist middle %016llx\n", key);
    // if remainder does not exist, will be either set to first remainder greater than hash_remainder
    // printf(" adding new keepsake in between\n");
    uint64_t slot_value = hash_remainder | (hash_memento << qf->metadata->key_remainder_bits);
    insert_one_slot(qf, hash_quotient, target_index, slot_value);
    METADATA_WORD(qf, runends, target_index) |= (1ULL << (target_index % 64));
    METADATA_WORD(qf, extensions, target_index) |= (1ULL << (target_index % 64));
      assert(run_end(qf, hash_quotient) == runend_index+1);
  } else {
      // printf("Remainder does not exist end %016llx\n", key);
    // if no remainder is greater, then target_index will be set to end of current_runend + 1.
    // printf(" adding new keepsake at end\n");
    uint64_t current_runend = run_end(qf, hash_quotient);
    assert(is_runend(qf, current_runend));
    assert(target_index == current_runend+1);
    uint64_t slot_value = hash_remainder | (hash_memento << qf->metadata->key_remainder_bits);
    insert_one_slot(qf, hash_quotient, target_index, slot_value);
    METADATA_WORD(qf, runends, target_index) |= (1ULL << (target_index % 64));
    METADATA_WORD(qf, extensions, current_runend) |= (1ULL << (current_runend % 64));
    assert(run_end(qf, hash_quotient) == runend_index+1);
  } 
  return 0;

}

// use the bulk_insert_sort function to ensure sorted order (to be implemented)
// also assumes the qf is empty
// assumes the item in the list have already been hashed
void qf_bulk_insert(const QF *qf, uint64_t *keys, int nkeys) {
	assert(qf->metadata->noccupied_slots == 0);
	assert(qf->metadata->nslots * 0.95 > nkeys);
	assert(nkeys > 0);
	
	uint64_t current_index = 0, current_run, current_rem, current_ext, current_ext_len = 0, current_count = 1, next_run, next_rem, next_ext;
	if (nkeys > 0) {
		current_run = (keys[0] >> qf->metadata->bits_per_slot) & BITMASK(qf->metadata->quotient_bits);
		current_rem = keys[0] & BITMASK(qf->metadata->bits_per_slot); // This should not be bits_per_slot, but fingerprint size.
		current_ext = keys[0] >> (qf->metadata->quotient_bits + qf->metadata->bits_per_slot);
		current_index = current_run;
		METADATA_WORD(qf, occupieds, current_run) |= (1ULL << (current_run % QF_SLOTS_PER_BLOCK));
	}
	for (int i = 1; i < nkeys; i++) {
		next_run = (keys[i] >> qf->metadata->bits_per_slot) & ((1 << qf->metadata->quotient_bits) - 1);
		next_rem = keys[i] & BITMASK(qf->metadata->bits_per_slot);
		next_ext = keys[i] >> (qf->metadata->quotient_bits + qf->metadata->bits_per_slot);
		if (next_run != current_run) { // if the next item will be in a new run, close the current run with a runend
			METADATA_WORD(qf, runends, current_index) |= (1ULL << (current_index % QF_SLOTS_PER_BLOCK));
			METADATA_WORD(qf, occupieds, next_run) |= (1ULL << (next_run % QF_SLOTS_PER_BLOCK));
		}
		else if (next_rem == current_rem) { // if the next item looks the same as the current item, we either need to extend or increment the counter
			if (keys[i] == keys[i - 1]) { // if the current and next item are duplicates, add to the counter and hold off (the item after that may again be a duplicate)
				current_count++;
			}
			else { // if the current and next item are different but just look the same, figure out how much to extend them by in order to differentiate them
				int next_ext_len = 1;
				uint64_t temp_curr_ext = current_ext;
				uint64_t temp_next_ext = next_ext;
				// figure out the minimum extension needed between the current and next item
				while ((temp_curr_ext & BITMASK(qf->metadata->bits_per_slot)) == (temp_next_ext & BITMASK(qf->metadata->bits_per_slot))) {
					next_ext_len++;
					temp_curr_ext >>= qf->metadata->bits_per_slot;
					temp_next_ext >>= qf->metadata->bits_per_slot;
				}
				// the current item must be long enough to differentiate from both the next and previous item
				current_index = _merge_insert(qf, current_index, current_run, current_rem, current_ext, next_ext_len > current_ext_len ? next_ext_len : current_ext_len, current_count);
				current_run = next_run;
				current_rem = next_rem;
				current_ext = next_ext;
				current_ext_len = next_ext_len;
				current_count = 1;
			}
			continue;
		}
		// no special relation between the current and next item; insert as usual
		// any relevant relation between the current and previous items is encoded in current_ext_len and current_count
		current_index = _merge_insert(qf, current_index, current_run, current_rem, current_ext, current_ext_len, current_count);
		current_run = next_run;
		if (current_index < current_run) current_index = current_run;
		current_rem = next_rem;
		current_ext = next_ext;
		current_ext_len = 0;
		current_count = 1;
	}
	if (nkeys > 0) {
		METADATA_WORD(qf, runends, current_index) |= (1ULL << (current_index % QF_SLOTS_PER_BLOCK));
		_merge_insert(qf, current_index, current_run, current_rem, current_ext, current_ext_len, current_count);
	}
}

/*
 * Merge an array of qfs into the resultant QF
 * DO NOT USE
 */
void qf_multi_merge(const QF *qf_arr[], int nqf, QF *qfr)
{
	int i;
	QFi qfi_arr[nqf];
	int smallest_idx = 0;
	uint64_t smallest_key = UINT64_MAX;
	for (i=0; i<nqf; i++) {
		if (qf_arr[i]->metadata->hash_mode != qfr->metadata->hash_mode &&
				qf_arr[i]->metadata->seed != qfr->metadata->seed) {
			fprintf(stderr, "Output QF and input QFs do not have the same hash mode or seed.\n");
			exit(1);
		}
		qf_iterator_from_position(qf_arr[i], &qfi_arr[i], 0);
	}

	DEBUG_CQF("Merging %d CQFs\n", nqf);
	for (i=0; i<nqf; i++) {
		DEBUG_CQF("CQF %d\n", i);
		DEBUG_DUMP(qf_arr[i]);
	}

	while (nqf > 1) {
		uint64_t keys[nqf];
		uint64_t values[nqf];
		uint64_t counts[nqf];
		for (i=0; i<nqf; i++);
			//qfi_get_hash(&qfi_arr[i], &keys[i], &counts[i]);
		
		do {
			smallest_key = UINT64_MAX;
			for (i=0; i<nqf; i++) {
				if (keys[i] < smallest_key) {
					smallest_key = keys[i]; smallest_idx = i;
				}
			}
			qf_insert(qfr, keys[smallest_idx], values[smallest_idx],
								counts[smallest_idx], QF_NO_LOCK | QF_KEY_IS_HASH);
			qfi_next(&qfi_arr[smallest_idx]);
			//qfi_get_hash(&qfi_arr[smallest_idx], &keys[smallest_idx], &counts[smallest_idx]);
		} while(!qfi_end(&qfi_arr[smallest_idx]));

		/* remove the qf that is exhausted from the array */
		if (smallest_idx < nqf-1)
			memmove(&qfi_arr[smallest_idx], &qfi_arr[smallest_idx+1],
							(nqf-smallest_idx-1)*sizeof(qfi_arr[0]));
		nqf--;
	}
	if (!qfi_end(&qfi_arr[0])) {
		uint64_t iters = 0;
		do {
			uint64_t key, value, count;
			//qfi_get_hash(&qfi_arr[0], &key, &count);
			qf_insert(qfr, key, value, count, QF_NO_LOCK | QF_KEY_IS_HASH);
			qfi_next(&qfi_arr[0]);
			iters++;
		} while(!qfi_end(&qfi_arr[0]));
		DEBUG_CQF("Num of iterations: %lu\n", iters);
	}

	DEBUG_CQF("%s", "Final CQF after merging.\n");
	DEBUG_DUMP(qfr);

	return;
}

/* DO NOT USE
 */
uint64_t qf_count_key_value(const QF *qf, uint64_t key, uint64_t value,
                                                                                                                uint8_t flags)
{
        if (GET_KEY_HASH(flags) != QF_KEY_IS_HASH) {
                if (qf->metadata->hash_mode == QF_HASH_DEFAULT)
                        key = MurmurHash64A(((void *)&key), sizeof(key), qf->metadata->seed);
                else if (qf->metadata->hash_mode == QF_HASH_INVERTIBLE)
                        key = hash_64(key, -1ULL);
        }
        uint64_t hash = (key << qf->metadata->value_bits) | (value & BITMASK(qf->metadata->value_bits)) % qf->metadata->range;
        uint64_t hash_remainder   = hash & BITMASK(qf->metadata->bits_per_slot);
        int64_t hash_bucket_index = hash >> qf->metadata->bits_per_slot;

        if (!is_occupied(qf, hash_bucket_index))
                return 0;

        int64_t runstart_index = hash_bucket_index == 0 ? 0 : run_end(qf, hash_bucket_index-1) + 1;
        if (runstart_index < hash_bucket_index)
                runstart_index = hash_bucket_index;

        /* printf("MC RUNSTART: %02lx RUNEND: %02lx\n", runstart_index, runend_index); */

        uint64_t current_remainder, current_count, current_end;
        do {
                //printf("2179");
                //current_end = decode_counter(qf, runstart_index, &current_remainder, &current_count);
                if (current_remainder == hash_remainder)
                        return current_count;
                runstart_index = current_end + 1;
        } while (!is_runend(qf, current_end));

        return 0;
}

/* find cosine similarity between two QFs. 
 * DO NOT USE
 * */
uint64_t qf_inner_product(const QF *qfa, const QF *qfb)
{
	uint64_t acc = 0;
	QFi qfi;
	const QF *qf_mem, *qf_disk;

	if (qfa->metadata->hash_mode != qfb->metadata->hash_mode &&
			qfa->metadata->seed != qfb->metadata->seed) {
		fprintf(stderr, "Input QFs do not have the same hash mode or seed.\n");
		exit(1);
	}

	// create the iterator on the larger QF.
	if (qfa->metadata->total_size_in_bytes > qfb->metadata->total_size_in_bytes)
	{
		qf_mem = qfb;
		qf_disk = qfa;
	} else {
		qf_mem = qfa;
		qf_disk = qfb;
	}

	qf_iterator_from_position(qf_disk, &qfi, 0);
	do {
		uint64_t key = 0, value = 0, count = 0;
		uint64_t count_mem;
		//qfi_get_hash(&qfi, &key, &count);
		if ((count_mem = qf_count_key_value(qf_mem, key, 0, QF_KEY_IS_HASH)) > 0) {
			acc += count*count_mem;
		}
	} while (!qfi_next(&qfi));

	return acc;
}

/* find cosine similarity between two QFs. 
 * DO NOT USE
 * */
void qf_intersect(const QF *qfa, const QF *qfb, QF *qfr)
{
	QFi qfi;
	const QF *qf_mem, *qf_disk;

	if (qfa->metadata->hash_mode != qfr->metadata->hash_mode &&
			qfa->metadata->seed != qfr->metadata->seed &&
			qfb->metadata->hash_mode  != qfr->metadata->hash_mode &&
			qfb->metadata->seed  != qfr->metadata->seed) {
		fprintf(stderr, "Output QF and input QFs do not have the same hash mode or seed.\n");
		exit(1);
	}

	// create the iterator on the larger QF.
	if (qfa->metadata->total_size_in_bytes > qfb->metadata->total_size_in_bytes)
	{
		qf_mem = qfb;
		qf_disk = qfa;
	} else {
		qf_mem = qfa;
		qf_disk = qfb;
	}

	qf_iterator_from_position(qf_disk, &qfi, 0);
	do {
		uint64_t key = 0, value = 0, count = 0;
		//qfi_get_hash(&qfi, &key, &count);
		if (qf_count_key_value(qf_mem, key, 0, QF_KEY_IS_HASH) > 0)
			qf_insert(qfr, key, value, count, QF_NO_LOCK | QF_KEY_IS_HASH);
	} while (!qfi_next(&qfi));
}

/* magnitude of a QF. 
 * DO NOT USE
 * */
uint64_t qf_magnitude(const QF *qf)
{
	return sqrt(qf_inner_product(qf, qf));
}
