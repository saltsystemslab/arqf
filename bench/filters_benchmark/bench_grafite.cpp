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
#include "grafite/grafite.hpp"

/**
 * This file contains the benchmark for the Grafite filter.
 */

std::string default_container = "sux";

template <typename REContainer, typename t_itr>
inline grafite::filter<REContainer> init_grafite(const t_itr begin, const t_itr end, bool load_keys, const double bpk)
{
    start_timer(build_time);
    grafite::filter<REContainer> filter(begin, end, bpk);
    stop_timer(build_time);
    return filter;
}

template <typename value_type, typename REContainer>
inline bool query_grafite(grafite::filter<REContainer> &f, const value_type left, const value_type right)
{
    return f.query(left, right);
}

template <typename REContainer>
inline size_t size_grafite(const grafite::filter<REContainer> &f)
{
    return f.size();
}

template <typename REContainer>
inline void add_metadata(const grafite::filter<REContainer> &f)
{
}

template <typename REContainer, typename value_type>
inline void insert_grafite(const grafite::filter<REContainer> &f, const value_type v)
{
}

template <typename REContainer, typename value_type>
inline bool adapt_grafite(grafite::filter<REContainer> &f, const value_type left, const value_type right)
{
  return false;
}

int main(int argc, char const *argv[])
{
    auto parser = init_parser("bench-grafite");
    parser.add_argument("--ds")
        .nargs(1)
        .default_value(default_container);

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

    auto container = parser.get<std::string>("ds");
    std::cout << "[+] using container `" << container << "`" << std::endl;
    if (test_type == "fpr") {
        if (container == "sux")
            experiment_fpr(
                pass_fun(init_grafite<grafite::ef_sux_vector>),
                pass_ref(query_grafite),
                pass_ref(adapt_grafite),
                pass_ref(size_grafite), 
                pass_ref(add_metadata),
                arg, keys, queries);
        else if (container == "sdsl")
            experiment_fpr(
                pass_fun(init_grafite<grafite::ef_sdsl_vector>),
                pass_ref(query_grafite),
                pass_ref(adapt_grafite),
                pass_ref(size_grafite), 
                pass_ref(add_metadata), 
                arg, keys, queries);
        else
            throw std::runtime_error("error, range emptiness data structure unknown.");
    } else if (test_type == "inserts") {
        if (container == "sux")
            experiment_inserts(
                pass_fun(init_grafite<grafite::ef_sux_vector>),
                pass_ref(query_grafite),
                pass_ref(adapt_grafite),
                pass_ref(size_grafite), 
                pass_ref(insert_grafite),
                pass_ref(add_metadata),
                arg, keys, queries);
        else if (container == "sdsl")
            experiment_inserts(
                pass_fun(init_grafite<grafite::ef_sdsl_vector>),
                pass_ref(query_grafite),
                pass_ref(adapt_grafite),
                pass_ref(size_grafite), 
                pass_ref(insert_grafite),
                pass_ref(add_metadata), 
                arg, keys, queries);
        else
            throw std::runtime_error("error, range emptiness data structure unknown.");
    } else if (test_type == "adversarial") {
        std::string db_home = parser.get<std::string>("keys");
        db_home += "_wtdb";
        if (container == "sux")
            experiment_adversarial_workload(
                pass_fun(init_grafite<grafite::ef_sux_vector>),
                pass_ref(query_grafite),
                pass_ref(adapt_grafite),
                pass_ref(size_grafite), 
                pass_ref(add_metadata),
                arg, db_home, keys, queries);
        else if (container == "sdsl")
            experiment_adversarial_workload(
                pass_fun(init_grafite<grafite::ef_sdsl_vector>),
                pass_ref(query_grafite),
                pass_ref(adapt_grafite),
                pass_ref(size_grafite), 
                pass_ref(add_metadata), 
                arg, db_home, keys, queries);
    }
    else {
        printf("Unsupported test type, aborting\n");
    }

    print_test();

    return 0;
}


