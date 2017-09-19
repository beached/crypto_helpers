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
	std::array<uint8_t, sha256_ctx<uint8_t>::DIGEST_SIZE> const expected_output = {
	    44, 242, 77, 186, 95, 176, 163, 14, 38,  232, 59, 42, 197, 185, 226, 158,
	    27, 22,  30, 92,  31, 167, 66,  94, 115, 4,   51, 98, 147, 139, 152, 36};

	BOOST_REQUIRE( std::equal( digest.cbegin( ), digest.cend( ), expected_output.cbegin( ), expected_output.cend( ) ) );
}

BOOST_AUTO_TEST_CASE( sha256_002 ) {
	BOOST_REQUIRE( sha256( "Hello World" ) == "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e" );
	BOOST_REQUIRE( sha256( "1184CD2CDD640CA42CFC3A091C51D549B2F016D454B2774019C2B2D2E08529FD" ) ==
	               "1c94d91f93ec9ed6bf647c384445b329c84a042c6b3832f8ee904dc55f117342" );
}

