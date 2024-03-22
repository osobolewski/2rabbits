cmake_minimum_required(VERSION 3.12...3.28)

project(2rabbits VERSION 1.0
        DESCRIPTION "Proof of Concept"
        LANGUAGES C)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

if (USE_STATIC_OPENSSL_LIBS) 
  set(OPENSSL_USE_STATIC_LIBS TRUE)
  set(OPENSSL_ROOT_DIR /etc/ssl)
  set(OPENSSL_CRYPTO_LIBRARY /usr/lib/libcrypto.so)
endif(USE_STATIC_OPENSSL_LIBS)

find_package(OpenSSL REQUIRED)

add_library(libfpe SHARED IMPORTED)
set_target_properties(libfpe PROPERTIES
  IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/dependencies/Format-Preserving-Encryption/libfpe.so"
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/dependencies/Format-Preserving-Encryption/src"
)

add_library(tworabbits 
                src/algorithms/2rabbits.h 
                src/algorithms/2rabbits.c 
                src/algorithms/rejection_sampling.c 
                src/algorithms/rejection_sampling.h 
                src/algorithms/advanced_sampling.c
                src/algorithms/advanced_sampling.h
                src/logger/logger.h 
                src/logger/logger.c 
                src/utils.h 
                src/utils.c
                src/anamorphic_ecdsa/ecdsa.h
                src/anamorphic_ecdsa/ecdsa.c)
target_link_libraries(tworabbits OpenSSL::Crypto libfpe)
target_include_directories(tworabbits PUBLIC src/algorithms src/logger)

add_executable(testsampling tests/rejection_sampling_test.c)
target_link_libraries(testsampling OpenSSL::Crypto tworabbits)
target_include_directories(testsampling PUBLIC src/algorithms src/logger)

add_executable(test2rabbits tests/2rabbits_test.c)
target_link_libraries(test2rabbits OpenSSL::Crypto tworabbits)
target_include_directories(test2rabbits PUBLIC src/algorithms src/logger)

add_executable(testadvanced tests/advanced_sampling_test.c)
target_link_libraries(testadvanced OpenSSL::Crypto tworabbits)
target_include_directories(testadvanced PUBLIC src/algorithms src/logger)

add_executable(testecdsa tests/ecdsa_test.c)
target_link_libraries(testecdsa OpenSSL::Crypto tworabbits)
target_include_directories(testecdsa PUBLIC src/algorithms src/logger)

add_executable(benchmark benchmarks/run_benchmarks.c)
target_link_libraries(benchmark OpenSSL::Crypto tworabbits)
target_include_directories(benchmark PUBLIC src/algorithms src/logger)
set_target_properties(benchmark
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/benchmarks"
)


add_executable(watermarking src/cli/watermarking_cli.c)
target_link_libraries(watermarking OpenSSL::Crypto tworabbits)
target_include_directories(watermarking PUBLIC src/algorithms src/logger)


