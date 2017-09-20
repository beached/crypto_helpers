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

#define BOOST_TEST_MODULE sha256_test

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>

#include <daw/boost_test.h>

#include "sha256.h"

using namespace daw::crypto;

BOOST_AUTO_TEST_CASE( sha256_001 ) {
	daw::string_view test_str = "hello";
	auto const digest = sha256_bin( test_str.cbegin( ), test_str.cend( ) );
	std::array<uint8_t, sha2_ctx<256, uint8_t>::digest_size> const expected_output = {
	    44, 242, 77, 186, 95, 176, 163, 14, 38,  232, 59, 42, 197, 185, 226, 158,
	    27, 22,  30, 92,  31, 167, 66,  94, 115, 4,   51, 98, 147, 139, 152, 36};

	BOOST_REQUIRE( std::equal( digest.data.cbegin( ), digest.data.cend( ), expected_output.cbegin( ), expected_output.cend( ) ) );
}

BOOST_AUTO_TEST_CASE( sha256_002 ) {
	BOOST_REQUIRE_EQUAL( sha256( "Hello World" ), "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e" );
	BOOST_REQUIRE_EQUAL( sha256( "grape" ), "0f78fcc486f5315418fbf095e71c0675ee07d318e5ac4d150050cd8e57966496" );
	BOOST_REQUIRE_EQUAL( sha256( "How are you" ), "9c7d5b046878838da72e40ceb3179580958df544b240869b80d0275cc07209cc" );
	BOOST_REQUIRE_EQUAL( sha256( "" ), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" );
	BOOST_REQUIRE_EQUAL( sha256( "1184CD2CDD640CA42CFC3A091C51D549B2F016D454B2774019C2B2D2E08529FD" ),
	                     "1c94d91f93ec9ed6bf647c384445b329c84a042c6b3832f8ee904dc55f117342" );
}

