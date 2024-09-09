#! /bin/bash

#
# This file is part of Grafite <https://github.com/marcocosta97/grafite>.
# Copyright (C) 2023 Marco Costa.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

if [ "$#" -ne 2 ]; then
    echo "Illegal number of parameters, usage: generate_datasets.sh <grafite_build_path> <real_datasets_path>"
fi

GRAFITE_BUILD_PATH=$(realpath $1)
if [ ! -d "$GRAFITE_BUILD_PATH" ]; then
  echo "Grafite build path does not exist"
  exit 1
fi

WORKLOAD_GEN_PATH=$(realpath $GRAFITE_BUILD_PATH/bench/workload_gen)
if [ ! -f "$WORKLOAD_GEN_PATH" ]; then
  echo "Workload generator does not exist"
  exit 1
fi

OUT_PATH=./workloads
generate_adversarial_test() {
  $WORKLOAD_GEN_PATH -n 200000000 -q 100000000 --mixed --kdist kuniform --qdist qcorrelated 
}

mkdir -p $OUT_PATH/adversarial_test && cd $OUT_PATH/adversarial_test || exit 1
if ! generate_adversarial_test ; then
  echo "[!!] adversarial test generation failed"
  exit 1
fi

echo "[!!] success, all datasets generated"
