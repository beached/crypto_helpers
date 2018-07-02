// The MIT License (MIT)
//
// Copyright (c) 2017-2018 Darrell Wright
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files( the "Software" ), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and / or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
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
#include <daw/daw_static_array.h>
#include <daw/daw_string_view.h>

#include "sha256.h"

namespace {
	void do_console( ) noexcept {
		std::ios_base::sync_with_stdio( false );
		daw::crypto::sha256_ctx ctx{};
		daw::static_array_t<unsigned char, 1024> buffer = {0};
		auto io_ptr = reinterpret_cast<char *>( buffer.data( ) );
		std::streamsize read_count = 0;
		while( std::cin.good( ) &&
		       ( read_count = std::cin.readsome(
		           io_ptr, static_cast<std::streamsize>( buffer.size( ) ) ) ) >
		         0 ) {
			ctx.update( buffer.data( ), static_cast<size_t>( read_count ) );
		}
		std::cout << ctx.final( ).to_hex_string( ) << "  -\n";
	}

	void do_file( daw::string_view file_name ) noexcept {
		daw::filesystem::memory_mapped_file_t<unsigned char> mmf{file_name};
		if( !mmf ) {
			std::cerr << "Could not open file '" << file_name << "'\n";
			exit( EXIT_FAILURE );
		}
		daw::crypto::sha256_ctx ctx{};
		ctx.update( daw::make_array_view( mmf.data( ), mmf.size( ) ) );
		std::cout << ctx.final( ).to_hex_string( ) << " " << file_name << '\n';
	}
} // namespace

int main( int argc, char **argv ) {
	if( argc > 1 ) {
		do_file( argv[1] );
	} else {
		do_console( );
	}
	return EXIT_SUCCESS;
}
