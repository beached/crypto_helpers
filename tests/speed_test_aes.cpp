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

#include <daw/daw_benchmark.h>
#include <daw/daw_size_literals.h>
#include <daw/daw_utility.h>

#include "aes.h"

int main( int, char ** ) {
	using namespace daw::size_literals;
	auto const test_data = daw::make_random_data<uint8_t>( 50_MB );
	auto data_view = daw::make_array_view( test_data );
	std::vector<uint8_t> result;
	result.resize( 1_GB );
	auto result_view = daw::make_span( result );

	constexpr daw::static_array_t<uint8_t, daw::crypto::aes::impl::AES128_KEY_SIZE::value> const key = {
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	auto key_view = daw::make_array_view( key );

	daw::show_benchmark( data_view.size( ), "speed_test_aes_001",
	                     [&]( ) { daw::crypto::aes::aes_encrypt_128( data_view, key_view, result_view ); }, 2, 2 );

	return EXIT_SUCCESS;
}
