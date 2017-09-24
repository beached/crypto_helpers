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
#include <daw/daw_string_view.h>

#include "sha256.h"

template<typename GetData>
void do_sha256( GetData get_data, daw::string_view sv ) {
	using namespace daw::crypto;
	sha2_ctx<256, char> ctx{};
	std::array<char, sha256_ctx::block_size_bytes / 2> buffer = {0};
	std::streamsize count = 0;
	auto is_good = get_data( buffer, count );
	while( count > 0 ) {
		ctx.update( buffer.data( ), static_cast<uint32_t>( count ) );
		if( !is_good ) {
			break;
		}
		is_good = get_data( buffer, count );
	}
	auto const digest = ctx.final( );
	std::cout << digest.to_hex_string( ) << "  " << sv << '\n';
}

void do_file( daw::string_view file_name ) noexcept {
	daw::filesystem::memory_mapped_file_t<uint8_t> mmf{ file_name };
	if( !mmf ) {
		std::cerr << "Could not open file '" << file_name << "'\n";
		exit( EXIT_FAILURE );
	}
	std::cout << daw::crypto::sha256( mmf ) << " " << file_name << '\n';
}

int main( int argc, char **argv ) {
	if( argc > 1 ) {
		do_file( argv[1] );
	} else {
		do_sha256(
		    []( auto &buffer, auto &count ) {
			    std::istream_iterator<char> first{std::cin};
			    std::istream_iterator<char> last{};
			    size_t n = 0;
			    for( ; n < buffer.size( ) && first != last; ++n, ++first ) {
				    buffer[n] = *first;
			    }
			    count = static_cast<std::streamsize>( n );
			    return static_cast<bool>( std::cin );
		    },
		    "-" );
	}
	return EXIT_SUCCESS;
}

