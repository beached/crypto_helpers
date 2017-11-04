cmake_minimum_required( VERSION 2.8.12 )

project( crypto_helpers )

include( ExternalProject )

find_package( Boost 1.60.0 COMPONENTS system iostreams filesystem regex unit_test_framework REQUIRED )

enable_testing( )
add_definitions( -DBOOST_ALL_NO_LIB ) 

include (TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
	add_definitions( -DENDIAN_BIG )
else()
	add_definitions( -DENDIAN_LITTLE )
endif()

if( ${CMAKE_CXX_COMPILER_ID} STREQUAL 'MSVC' )
	add_compile_options( -D_WIN32_WINNT=0x0601 /std:c++latest ) 
else( )
	if( ${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang" OR ${CMAKE_CXX_COMPILER_ID} STREQUAL "AppleClang" )
		add_compile_options(-std=c++14 -march=native -flto=thin -Weverything -Wno-missing-braces -Wno-c++98-compat -Wno-covered-switch-default -Wno-padded -Wno-exit-time-destructors -Wno-c++98-compat-pedantic -Wno-unused-parameter -Wno-missing-noreturn -Wno-missing-prototypes -Wno-disabled-macro-expansion)
		set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
		set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
		set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto=thin" )
	elseif( ${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU" )
		add_compile_options(-std=c++14 -flto -march=native -Wall -Wnonnull -Wno-deprecated-declarations)
		set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
		set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
		set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto" )
	endif( )
endif( )

externalproject_add(
    header_libraries_prj
    GIT_REPOSITORY "https://github.com/beached/header_libraries.git"
    SOURCE_DIR "${CMAKE_BINARY_DIR}/dependencies/header_libraries"
    GIT_TAG "master"
    INSTALL_DIR "${CMAKE_BINARY_DIR}/install"
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/install
)

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
add_dependencies( sha256_test_bin header_libraries_prj )
add_test( sha256_test sha256_test_bin )

add_executable( sha256sum ${SHA256_HEADER_FILES} ${SOURCE_FOLDER}/sha256sum.cpp )
target_link_libraries( sha256sum ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} )
add_dependencies( sha256sum header_libraries_prj )

add_executable( constexpr ${SHA256_HEADER_FILES} ${TEST_FOLDER}/constexpr.cpp )
target_link_libraries( constexpr ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} )
add_dependencies( constexpr header_libraries_prj )
add_test( constexpr_test constexpr )

add_executable( speed_test_sha256 ${SHA256_HEADER_FILES} ${TEST_FOLDER}/speed_test_sha256.cpp )
target_link_libraries( speed_test_sha256 ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} )
add_dependencies( speed_test_sha256 header_libraries_prj )
add_test( speed_test_sha256_test speed_test_256 )

add_executable( speed_test_aes ${SHA256_HEADER_FILES} ${TEST_FOLDER}/speed_test_aes.cpp )
target_link_libraries( speed_test_aes ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} )
add_dependencies( speed_test_aes header_libraries_prj )
add_test( speed_test_aes_test speed_test_aes )

add_executable( aes_test_bin ${AES_HEADER_FILES} ${TEST_FOLDER}/aes_test.cpp )
target_link_libraries( aes_test_bin ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} )
add_dependencies( aes_test_bin header_libraries_prj )
add_test( aes_test aes_test_bin )

install( DIRECTORY ${HEADER_FOLDER}/ DESTINATION include/daw/crypto )

