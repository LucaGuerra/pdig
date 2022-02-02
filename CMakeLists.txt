cmake_minimum_required (VERSION 2.6)

project(pdig)

if(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE Release)
endif()

# Add path for custom CMake modules.
list(APPEND CMAKE_MODULE_PATH
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

option(MUSL_OPTIMIZED_BUILD "Enable if you want a musl optimized build" OFF)

if(MUSL_OPTIMIZED_BUILD)
  set(MUSL_OPTIMIZED_BUILD_FLAGS "-static -Os -DMUSL_OPTIMIZED")
endif()

add_definitions(-DUDIG)
set(CMAKE_C_FLAGS_DEBUG "-Og -g -D_DEBUG -Wall ${MUSL_OPTIMIZED_BUILD_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "-Og -g -D_DEBUG -Wall ${MUSL_OPTIMIZED_BUILD_FLAGS}")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG -Wall ${MUSL_OPTIMIZED_BUILD_FLAGS}")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -Wall ${MUSL_OPTIMIZED_BUILD_FLAGS}")

if(NOT FALCO_LIBS_DIR)
	SET(FALCO_LIBS_DIR ../libs)
endif()

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${FALCO_LIBS_DIR}/driver)
include_directories(${FALCO_LIBS_DIR}/userspace/libscap)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

if(NOT MUSL_OPTIMIZED_BUILD)
    include(protobuf)
endif()

add_custom_command(
    OUTPUT
    # ${CMAKE_CURRENT_BINARY_DIR}/common.pb.cc
    # ${CMAKE_CURRENT_BINARY_DIR}/common.pb.h
    # ${CMAKE_CURRENT_BINARY_DIR}/container.pb.cc
    # ${CMAKE_CURRENT_BINARY_DIR}/container.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/syscall.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/syscall.pb.h
    COMMENT "Generate protobuf files"
    # syscall
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/syscall.proto
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR} --cpp_out=. ${CMAKE_CURRENT_SOURCE_DIR}/syscall.proto
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

add_executable(pdig
    pdig.cc
	pdig_compat.c
	pdig_ptrace.c
	pdig_ptrace_amd64.cc
	pdig_seccomp.cc
	proc_tree.cc
    udig_procs.c
    pdig_gvisor.cc
    syscall.pb.cc
    ${FALCO_LIBS_DIR}/driver/dynamic_params_table.c
    ${FALCO_LIBS_DIR}/driver/event_table.c
    ${FALCO_LIBS_DIR}/driver/flags_table.c
    ${FALCO_LIBS_DIR}/driver/ppm_events.c
    ${FALCO_LIBS_DIR}/driver/ppm_fillers.c
    ${FALCO_LIBS_DIR}/driver/fillers_table.c
    ${FALCO_LIBS_DIR}/driver/syscall_table.c
    ${FALCO_LIBS_DIR}/userspace/libscap/scap_udig.c
)

target_link_libraries(pdig rt protobuf pthread)

set_property(TARGET pdig PROPERTY CXX_STANDARD 11)
