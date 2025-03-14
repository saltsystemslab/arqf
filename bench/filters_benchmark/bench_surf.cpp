/*
 * This file is part of Grafite <https://github.com/marcocosta97/grafite>.
 * Copyright (C) 2023 Marco Costa.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "../bench_template.hpp"
#include "../filters/SuRF/include/surf.hpp"
/**
 * This file contains the benchmark for the SuRF filter.
 */

template <typename t_itr, typename... Args>
inline surf::SuRF init_surf(const t_itr begin, const t_itr end, bool load_keys, const int suffix_bits, Args... args)
{
    std::vector<std::string> string_keys(std::distance(begin, end));
    std::transform(begin, end, string_keys.begin(), [&](auto k)
    { return uint64ToString(k); });
    start_timer(build_time);
    auto s = surf::SuRF(string_keys, surf::kReal, 0, suffix_bits);
    stop_timer(build_time);
    return s;
}

template <typename t_itr, typename... Args>
inline surf::SuRF init_surf_hash(const t_itr begin, const t_itr end, const int suffix_bits, Args... args)
{
    std::vector<std::string> string_keys(std::distance(begin, end));
    std::transform(begin, end, string_keys.begin(), [&](auto k)
    { return uint64ToString(k); });
    start_timer(build_time);
    auto s = surf::SuRF(string_keys, surf::kHash, suffix_bits, 0);
    stop_timer(build_time);
    return s;
}

inline bool query_surf(surf::SuRF &f, const uint64_t left, const uint64_t right)
{
    if (left == right)
        return f.lookupKey(uint64ToString(left));
    return f.lookupRange(uint64ToString(left), true, uint64ToString(right), true);
}
inline size_t size_surf(surf::SuRF &f)
{
    return f.serializedSize();
}

template <typename value_type>
inline bool adapt_surf(surf::SuRF &f, const value_type left, const value_type right)
{
  return false;
}

inline void add_metadata(surf::SuRF &f)
{
}

template <typename value_type>
inline void insert_surf(surf::SuRF &f, const value_type v) {
    // SuRF does not support inserts.
}



int main(int argc, char const *argv[])
{
    auto parser = init_parser("bench-surf");

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

    auto [ keys, queries, arg ] = read_parser_arguments(parser);
    auto test_type = parser.get<std::string>("--test-type");
    auto surf_hash = true;

    // Check if all the queries are point queries, if so we use the hash version of SuRF, otherwise we use the real version.
    for (auto & it : queries)
        if (std::get<0>(it) != std::get<1>(it))
        {
            surf_hash = false;
            break;
        }
  

    if (test_type == "fpr") {
    if (surf_hash)
        experiment_fpr(
            pass_fun(init_surf_hash),
            pass_ref(query_surf),
            pass_ref(adapt_surf),
            pass_ref(size_surf), 
            pass_ref(add_metadata),
            arg, keys, queries);
    else
        experiment_fpr(
            pass_fun(init_surf),
            pass_ref(query_surf),
            pass_ref(adapt_surf),
            pass_ref(size_surf), 
            pass_ref(add_metadata),
            arg, 
            keys, 
            queries);
    } else if (test_type == "inserts") {
        experiment_inserts(
            pass_fun(init_surf),
            pass_ref(query_surf),
            pass_ref(adapt_surf),
            pass_ref(size_surf), 
            pass_ref(insert_surf),
            pass_ref(add_metadata),
            arg, 
            keys, 
            queries
        );
    } else if (test_type == "adversarial") {
        std::string db_home = parser.get<std::string>("keys");
        db_home += "_wtdb";
        if (surf_hash) {
            experiment_adversarial_workload(
                pass_fun(init_surf_hash),
                pass_ref(query_surf),
                pass_ref(adapt_surf),
                pass_ref(size_surf), 
                pass_ref(add_metadata), 
                arg, 
                db_home,
                keys, 
                queries,
                queries);
        } else {
            experiment_adversarial_workload(
                pass_fun(init_surf),
                pass_ref(query_surf),
                pass_ref(adapt_surf),
                pass_ref(size_surf), 
                pass_ref(add_metadata), 
                arg, 
                db_home,
                keys, 
                queries,
                queries);

        }
    } 
    else {
        printf("Unsupported test, aborting\n");
        abort(); // Unsupported test.
    }
    print_test();

    return 0;
}
