.PHONY: datasets build_bench

clean:
	rm -rf build

build_bench:
	mkdir -p build
	cd build && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j8

datasets: build_bench
	mkdir -p paper_results
	cd paper_results && bash ../bench/scripts/download_datasets.sh
	bash ./bench/scripts/generate_datasets.sh ./build ../paper_results/real_datasets

