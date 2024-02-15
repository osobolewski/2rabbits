cmake_minimum_required(VERSION 3.12...3.28)

project(2rabbits VERSION 1.0
        DESCRIPTION "Proof of Concept"
        LANGUAGES C)

set(OPENSSL_USE_STATIC_LIBS TRUE)
set(OPENSSL_ROOT_DIR /usr/include/openssl/)
set(OPENSSL_CRYPTO_LIBRARY /usr/lib/libcrypto.so)
find_package(OpenSSL REQUIRED)

add_library(rsampling STATIC src/algorithms/rejection_sampling.c src/algorithms/rejection_sampling.h src/logger/logger.h src/logger/logger.c)

target_include_directories(rsampling PUBLIC src/algorithms)

add_executable(testsampling tests/rejection_sampling_test.c src/algorithms/rejection_sampling.c src/algorithms/rejection_sampling.h src/logger/logger.h src/logger/logger.c src/utils.h src/utils.c)
target_link_libraries(testsampling OpenSSL::Crypto)
target_include_directories(testsampling PUBLIC src/algorithms src/logger)
