#include <map>
#include <vector>
#include <argparse/argparse.hpp>
#include <string.h>
#include "../bench_utils.hpp"
#include <chrono>
#include "splinter_util.h"

#define MAX_VALUE(nbits) ((1ULL << (nbits)) - 1)
#define BITMASK(nbits)                                    \
  ((nbits) == 64 ? 0xffffffffffffffff : MAX_VALUE(nbits))

template<typename KeyType>
using Workload = std::vector<std::tuple<KeyType, KeyType, bool>>;
template<typename KeyType>
using InputKeys = std::vector<KeyType>;

inline uint64_t MurmurHash64A(const void * key, int len, unsigned int seed)
{
	const uint64_t m = 0xc6a4a7935bd1e995;
	const int r = 47;

	uint64_t h = seed ^ (len * m);

	const uint64_t * data = (const uint64_t *)key;
	const uint64_t * end = data + (len/8);

	while(data != end) {
		uint64_t k = *data++;

		k *= m;
		k ^= k >> r;
		k *= m;

		h ^= k;
		h *= m;
	}

	const unsigned char * data2 = (const unsigned char*)data;

	switch(len & 7) {
		case 7: h ^= (uint64_t)data2[6] << 48; do {} while (0);  /* fallthrough */
		case 6: h ^= (uint64_t)data2[5] << 40; do {} while (0);  /* fallthrough */
		case 5: h ^= (uint64_t)data2[4] << 32; do {} while (0);  /* fallthrough */
		case 4: h ^= (uint64_t)data2[3] << 24; do {} while (0);  /* fallthrough */
		case 3: h ^= (uint64_t)data2[2] << 16; do {} while (0);  /* fallthrough */
		case 2: h ^= (uint64_t)data2[1] << 8; do {} while (0); /* fallthrough */
		case 1: h ^= (uint64_t)data2[0];
						h *= m;
	};

	h ^= h >> r;
	h *= m;
	h ^= h >> r;

	return h;
}

__attribute__((always_inline))
static inline uint32_t fast_reduce(uint32_t hash, uint32_t n) {
    // http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
    return (uint32_t) (((uint64_t) hash * n) >> 32);
}

static inline uint64_t hash(uint64_t key, uint64_t quotient_bits, uint64_t remainder_bits, uint64_t memento_bits, uint64_t n_slots, uint64_t seed ) {
  const uint64_t quotient_mask = (1ULL << quotient_bits) - 1;
  const uint64_t memento_mask = (1ULL << memento_bits) - 1;
  const uint64_t hash_mask = (1ULL << (quotient_bits + remainder_bits)) - 1;
  // WARNING: Don't use auto here. For some reason, using auto y, results in sizeof(y)=4
  // TODO(chesetti): Find out why this is the case.
  uint64_t y = key >> memento_bits;
  uint64_t mhash = MurmurHash64A(((void*)&y), sizeof(y), seed);
  // Use the lower order q bits of mhash to determine address.
  const uint64_t address = fast_reduce((mhash & quotient_mask) << (32 - quotient_bits),
      n_slots);
  // Use the lower order r (after q bits) of mhash to determine reminder.
  uint64_t hash = ((mhash & hash_mask) >> quotient_bits) | (address << remainder_bits);
  // Fill the higher order bits with bits from the MurmurHash, these will be used as extensions.
  hash = hash | (mhash & ~BITMASK(quotient_bits + remainder_bits));
  return hash;
}

uint64_t num_reads, num_writes;
uint64_t splinter_cache_size;

argparse::ArgumentParser init_parser(const std::string &name) {
    argparse::ArgumentParser parser(name);
    parser.add_argument("arg")
            .help("the main parameter of the ds (typically desired bpk o #suffix bits)")
            .scan<'g', double>();
    parser.add_argument("-k", "--keys")
            .help("pass the keys from file")
            .nargs(1);
    parser.add_argument("-r", "--reads")
            .help("num reads (should be less than num keys")
            .scan<'u', uint64_t>()
            .nargs(1);
    parser.add_argument("-w", "--writes")
            .help("num writes (should be less than num keys")
            .scan<'u', uint64_t>()
            .nargs(1);
    parser.add_argument("-c", "--splinter_cache_size_mb")
            .help("Splinter Cache Size")
            .scan<'u', uint64_t>()
            .nargs(1);
    return parser;
}

std::tuple<InputKeys<uint64_t>,  double> read_parser_arguments(argparse::ArgumentParser &parser) {
    auto arg = parser.get<double>("arg");
    splinter_cache_size = parser.get<uint64_t>("splinter_cache_size_mb");
    num_reads = parser.get<uint64_t>("reads");
    num_writes = parser.get<uint64_t>("writes");

    std::cout<<splinter_cache_size<<" "<<num_reads<<" "<<num_writes<<std::endl;

    auto keys_filename = parser.get<std::string>("keys");
    auto keys = read_data_binary<uint64_t>(keys_filename);

    return std::make_tuple(keys, arg);
}

#define start_timer(t) \
    auto t_start_##t = timer::now(); \

#define end_timer(t) \
    auto t_end_##t = timer::now(); \
    auto t_duration_##t = std::chrono::duration_cast<std::chrono::nanoseconds>(t_end_##t - t_start_##t).count();

void profile_splinter(std::vector<std::pair<uint64_t, uint64_t> > fingerprints) {
    data_config* data_cfg;
    splinterdb_config* splinterdb_cfg;
    splinterdb* db;
    qf_init_splinterdb(&db, &data_cfg, &splinterdb_cfg, "rhm5", splinter_cache_size, 24);

    std::cout << "(-) starting bulk load" << std::endl;

    uint64_t total_keys_inserted = 0;
    std::vector<uint64_t> latency_samples;
    std::vector<uint64_t> avg_message_size;

    uint64_t count_writes = 0;
    start_timer(insert);
    for (auto fingerprint_entry : fingerprints) {
        uint64_t fingerprint = fingerprint_entry.first;
        uint64_t key = fingerprint_entry.second;
        db_insert(db, &fingerprint, sizeof(fingerprint), &key, sizeof(uint64_t), 1, 0);
        count_writes++;
        if (count_writes == num_writes)break;
    }
    end_timer(insert);
    std::cout << "(+) bulk load completed" << std::endl;
    start_timer(close);
    qf_splinterdb_close(db);
    end_timer(close);
    std::cout << "(+) bulk load completed" << std::endl;
    std::cout<<"Splinter Cache Size: " << splinter_cache_size <<"MB"<<std::endl;
    std::cout<<"Num inserts: " << count_writes <<std::endl;
    std::cout<<"Insert Throughput: (ops/sec) " << 1e9 * count_writes / (t_duration_insert) << std::endl;; 
    std::cout<<"Close duration: (usec) " << (t_duration_close / 1e6) << std::endl;; 

#if 0
    double average_val_size = (1.0 * total_keys_inserted / count_writes) * 8;

    splinterdb_lookup_result *lookup_result;
    init_db_lookup(db, &lookup_result);
    uint64_t count_reads = 0; // Fix this name...

    start_timer(read);
    for (auto rhm_entry: rhm) {
        count_reads++;
        if (count_reads == num_reads) break;
        uint64_t *colliding_keys;
        uint64_t num_colliding_keys;
        uint64_t fingerprint = rhm_entry.first;
        db_lookup(db, lookup_result, fingerprint, &colliding_keys, &num_colliding_keys);

        if (num_colliding_keys != rhm_entry.second.size()) {
            abort();
        }
        uint64_t xor_rhm = 0;
        for (auto key_in_rhm : rhm_entry.second) {
            xor_rhm ^= key_in_rhm;
        }
        uint64_t xor_splinterdb = 0;
        for (uint64_t i=0; i < num_colliding_keys; i++) {
            xor_splinterdb ^= colliding_keys[i];
        }

        if (xor_rhm != xor_splinterdb) {
            abort();
        }
    }
    end_timer(read);
#endif

}

int main(int argc, char **argv) {
    // Init Flags.
    auto parser = init_parser("bench-splinter");
    try
    {
        parser.parse_args(argc, argv);
    }
    catch (const std::runtime_error &err)
    {
        std::cerr << err.what() << std::endl;
        std::cerr << parser;
        std::exit(1);
    }
    // Read the keys in input file
    auto [ keys, bpk ] = read_parser_arguments(parser);
    std::cout<<"[+] keys and queries loaded"<< std::endl;

    uint64_t quotient_bits = 0;
    while ((1ULL << quotient_bits) < keys.size())
        quotient_bits++;
    uint64_t memento_bits = 2;
    uint64_t remainder_bits = round(bpk * 0.95 - memento_bits - 2.125);
    std::vector<std::pair<uint64_t, uint64_t>> fingerprints;
    std::map<uint64_t, std::vector<uint64_t>> rhm;
    for (auto key : keys) {
        uint64_t fingerprint = hash(key, quotient_bits, remainder_bits, memento_bits, keys.size(), 1380);
        fingerprints.push_back(std::make_pair(fingerprint, key));
        rhm[fingerprint].push_back(key);
        if (fingerprints.size() == num_writes) {
            break;
        }
    }

    profile_splinter(fingerprints);

    // Insert fingerprint
    // Measure latency
    //      - Check if it matches what you're seeing in the paper
    //      - Check if it matches what you're seeing in your code 
    // Vary cache size & vary bulk insert or separate messages.
    return 0;
}