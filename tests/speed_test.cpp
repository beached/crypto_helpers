// The MIT License (MIT)
//
// Copyright (c) 2017 Darrell Wright
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files( the "Software" ), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <random>

#include <daw/daw_benchmark.h>
#include <daw/daw_size_literals.h>

#include "sha256.h"

template<typename Iterator>
void fill_random( Iterator first, Iterator last ) {
	std::random_device rnd_device;
	// Specify the engine and distribution.
	std::mt19937 mersenne_engine{rnd_device( )};
	std::uniform_int_distribution<int64_t> dist{0, 255};

	std::generate( first, last, [&]( ) { return dist( mersenne_engine ); } );
}

int main( int, char** ) {
	using namespace daw::size_literals;
	std::vector<uint8_t> test_data;
	test_data.resize( 1_GB );
	fill_random( test_data.begin( ), test_data.end( ) );
	auto view = daw::make_array_view( test_data.data( ), test_data.size( ) );
	daw::show_benchmark( view.size( ), "test001", [&view]( ) {
		daw::crypto::sha256_ctx ctx{};
		ctx.update( view );
		ctx.final( );
	} );

	return EXIT_SUCCESS;
}


