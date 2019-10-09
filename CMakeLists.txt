cmake_minimum_required(VERSION 3.13)
project( crypto_helpers )

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

include("${CMAKE_SOURCE_DIR}/glean/CMakeListsCompiler.txt")
include("${CMAKE_SOURCE_DIR}/glean/CMakeLists.txt")

find_package(Boost 1.60 COMPONENTS unit_test_framework REQUIRED)
include_directories(SYSTEM ${Boost_INCLUDE_DIRS})
link_directories(${Boost_LIBRARY_DIRS})

include_directories("${CMAKE_SOURCE_DIR}/include")


enable_testing( )
add_definitions( -DBOOST_ALL_NO_LIB ) 

include (TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
	add_definitions( -DENDIAN_BIG )
else()
	add_definitions( -DENDIAN_LITTLE )
endif()

set( HEADER_FOLDER "include" )
set( SOURCE_FOLDER "src" )
set( TEST_FOLDER "tests" )

include_directories( SYSTEM "${CMAKE_BINARY_DIR}/install/include" )
include_directories( ${HEADER_FOLDER} )

include_directories( SYSTEM ${Boost_INCLUDE_DIRS} )

link_directories( "${CMAKE_BINARY_DIR}/install/lib" )
link_directories( ${Boost_LIBRARY_DIRS} )

set( SHA256_HEADER_FILES
	${HEADER_FOLDER}/sha256.h
)

set( AES_HEADER_FILES
	${HEADER_FOLDER}/aes.h
)

add_definitions( -DBOOST_TEST_DYN_LINK -DBOOST_ALL_NO_LIB -DBOOST_ALL_DYN_LINK )

add_executable( sha256_test_bin ${SHA256_HEADER_FILES} ${TEST_FOLDER}/sha256_test.cpp )
target_link_libraries( sha256_test_bin ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} )
add_test( sha256_test sha256_test_bin )

add_executable( sha256sum ${SHA256_HEADER_FILES} ${SOURCE_FOLDER}/sha256sum.cpp )
target_link_libraries( sha256sum ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} )

add_executable( constexpr ${SHA256_HEADER_FILES} ${TEST_FOLDER}/constexpr.cpp )
target_link_libraries( constexpr ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} )
add_test( constexpr_test constexpr )

add_executable( speed_test_sha256 ${SHA256_HEADER_FILES} ${TEST_FOLDER}/speed_test_sha256.cpp )
target_link_libraries( speed_test_sha256 ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} )
add_test( speed_test_sha256_test speed_test_256 )

add_executable( speed_test_aes ${SHA256_HEADER_FILES} ${TEST_FOLDER}/speed_test_aes.cpp )
target_link_libraries( speed_test_aes ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} )
add_test( speed_test_aes_test speed_test_aes )

add_executable( aes_test_bin ${AES_HEADER_FILES} ${TEST_FOLDER}/aes_test.cpp )
target_link_libraries( aes_test_bin ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} )
add_test( aes_test aes_test_bin )

install( DIRECTORY ${HEADER_FOLDER}/ DESTINATION include/daw/crypto )

