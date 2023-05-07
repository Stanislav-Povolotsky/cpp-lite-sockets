#!/bin/bash
set -e
build_folder_base=./build/nix/`uname -r`

cfg_type=Debug
build_folder=$build_folder_base/$cfg_type
cmake -DCMAKE_BUILD_TYPE=$cfg_type -S . -B $build_folder && cmake --build $build_folder && ./$build_folder/unit_tests

cfg_type=Release
build_folder=$build_folder_base/$cfg_type
cmake -DCMAKE_BUILD_TYPE=$cfg_type -S . -B $build_folder && cmake --build $build_folder && ./$build_folder/unit_tests