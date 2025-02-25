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
#include "../filters/SNARF/include/snarf.cpp"
/**
 * This file contains the benchmark for the SNARF filter.
 */

template <typename t_itr>
inline snarf_updatable_gcs<typename t_itr::value_type> init_snarf(const t_itr begin, const t_itr end, bool load_keys, const double bpk)
{
    std::vector<typename t_itr::value_type> keys(begin, end);
    start_timer(build_time);
    snarf_updatable_gcs<typename t_itr::value_type> f;
    f.snarf_init(keys, bpk, 100);
    stop_timer(build_time);
    return f;
}

template <typename value_type>
inline bool query_snarf(snarf_updatable_gcs<value_type> &f, const value_type left, const value_type right)
{
    return f.range_query(left, right);
}

template <typename value_type>
inline size_t size_snarf(snarf_updatable_gcs<value_type> &f)
{
    return f.return_size();
}

template <typename value_type>
inline bool adapt_snarf(snarf_updatable_gcs<value_type> &f, const value_type left, const value_type right)
{
  return false;
}

template <typename value_type>
inline void add_metadata(snarf_updatable_gcs<value_type> &f)
{
}

template <typename value_type>
inline void insert_snarf(snarf_updatable_gcs<value_type> &f, const value_type v)
{
    f.insert_key(v);
}

int main(int argc, char const *argv[])
{
    auto parser = init_parser("bench-snarf");
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
    if (test_type == "fpr") {
        experiment_fpr(
            pass_fun(init_snarf),
            pass_ref(query_snarf),
            pass_ref(adapt_snarf),
            pass_ref(size_snarf), 
            pass_ref(add_metadata),
            arg, keys, queries
        );
    } else if (test_type == "inserts") {
        experiment_inserts(
            pass_fun(init_snarf),
            pass_ref(query_snarf),
            pass_ref(adapt_snarf),
            pass_ref(size_snarf), 
            pass_ref(insert_snarf),
            pass_ref(add_metadata),
            arg, keys, queries
        );
    } else if (test_type == "adversarial") {
        std::string db_home = parser.get<std::string>("keys");
        db_home += "_wtdb";
        experiment_adversarial_workload(
            pass_fun(init_snarf),
            pass_ref(query_snarf),
            pass_ref(adapt_snarf),
            pass_ref(size_snarf), 
            pass_ref(add_metadata),
            arg, db_home, keys, queries
        );
    } 
    else {
        printf("Unsupported test type, aborting\n");
        abort();
    }
    print_test();

    return 0;
}
