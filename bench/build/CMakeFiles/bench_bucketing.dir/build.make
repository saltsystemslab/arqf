# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.28

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/chesetti/Repos/arqf/arqf/bench

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/chesetti/Repos/arqf/arqf/bench/build

# Include any dependencies generated for this target.
include CMakeFiles/bench_bucketing.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/bench_bucketing.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/bench_bucketing.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/bench_bucketing.dir/flags.make

CMakeFiles/bench_bucketing.dir/filters_benchmark/bench_bucketing.cpp.o: CMakeFiles/bench_bucketing.dir/flags.make
CMakeFiles/bench_bucketing.dir/filters_benchmark/bench_bucketing.cpp.o: /home/chesetti/Repos/arqf/arqf/bench/filters_benchmark/bench_bucketing.cpp
CMakeFiles/bench_bucketing.dir/filters_benchmark/bench_bucketing.cpp.o: CMakeFiles/bench_bucketing.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/chesetti/Repos/arqf/arqf/bench/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/bench_bucketing.dir/filters_benchmark/bench_bucketing.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/bench_bucketing.dir/filters_benchmark/bench_bucketing.cpp.o -MF CMakeFiles/bench_bucketing.dir/filters_benchmark/bench_bucketing.cpp.o.d -o CMakeFiles/bench_bucketing.dir/filters_benchmark/bench_bucketing.cpp.o -c /home/chesetti/Repos/arqf/arqf/bench/filters_benchmark/bench_bucketing.cpp

CMakeFiles/bench_bucketing.dir/filters_benchmark/bench_bucketing.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/bench_bucketing.dir/filters_benchmark/bench_bucketing.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/chesetti/Repos/arqf/arqf/bench/filters_benchmark/bench_bucketing.cpp > CMakeFiles/bench_bucketing.dir/filters_benchmark/bench_bucketing.cpp.i

CMakeFiles/bench_bucketing.dir/filters_benchmark/bench_bucketing.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/bench_bucketing.dir/filters_benchmark/bench_bucketing.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/chesetti/Repos/arqf/arqf/bench/filters_benchmark/bench_bucketing.cpp -o CMakeFiles/bench_bucketing.dir/filters_benchmark/bench_bucketing.cpp.s

# Object files for target bench_bucketing
bench_bucketing_OBJECTS = \
"CMakeFiles/bench_bucketing.dir/filters_benchmark/bench_bucketing.cpp.o"

# External object files for target bench_bucketing
bench_bucketing_EXTERNAL_OBJECTS =

bench_bucketing: CMakeFiles/bench_bucketing.dir/filters_benchmark/bench_bucketing.cpp.o
bench_bucketing: CMakeFiles/bench_bucketing.dir/build.make
bench_bucketing: CMakeFiles/bench_bucketing.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/chesetti/Repos/arqf/arqf/bench/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable bench_bucketing"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/bench_bucketing.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/bench_bucketing.dir/build: bench_bucketing
.PHONY : CMakeFiles/bench_bucketing.dir/build

CMakeFiles/bench_bucketing.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/bench_bucketing.dir/cmake_clean.cmake
.PHONY : CMakeFiles/bench_bucketing.dir/clean

CMakeFiles/bench_bucketing.dir/depend:
	cd /home/chesetti/Repos/arqf/arqf/bench/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/chesetti/Repos/arqf/arqf/bench /home/chesetti/Repos/arqf/arqf/bench /home/chesetti/Repos/arqf/arqf/bench/build /home/chesetti/Repos/arqf/arqf/bench/build /home/chesetti/Repos/arqf/arqf/bench/build/CMakeFiles/bench_bucketing.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/bench_bucketing.dir/depend

