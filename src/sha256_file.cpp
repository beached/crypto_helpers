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
#include <fstream>
#include <iostream>

#include <daw/daw_memory_mapped_file.h>

#include "sha256.h"

int main( int argc, char **argv ) {
	assert( argc >= 1 );
	using namespace daw::crypto;
	sha2_ctx<256, char> ctx{};
	std::array<char, sha2_ctx<256, char>::block_size/2> buffer = {0};

	std::ifstream in_file{argv[1], std::ios::binary};
	assert( in_file );
	auto count = in_file.readsome( buffer.data( ), static_cast<std::streamsize>( buffer.size( ) ) );
	while( count > 0 ) {
		ctx.update( buffer.data( ), static_cast<uint32_t>( count ) );
		if( !in_file ) {
			break;
		}
		count = in_file.readsome( buffer.data( ), static_cast<std::streamsize>( buffer.size( ) ) );
	}
	auto digest = ctx.final( );

	std::cout << digest.to_hex_string( ) << "  " << argv[1] << '\n';
	return EXIT_SUCCESS;
}

