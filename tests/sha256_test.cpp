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

BOOST_AUTO_TEST_CASE( sha256_006 ) {
	BOOST_REQUIRE_EQUAL( sha256( "" ), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" );
}

BOOST_AUTO_TEST_CASE( sha256_001 ) {
	BOOST_REQUIRE_EQUAL( sha256( "abc" ), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" );
}

BOOST_AUTO_TEST_CASE( sha256_002 ) {
	daw::string_view test_str = "hello";
	auto const digest = sha256_bin( test_str );
	std::array<uint32_t, sha256_ctx::digest_size> const expected_output = {
	    0x2cf24dba, 0x5fb0a30e, 0x26e83b2a, 0xc5b9e29e, 0x1b161e5c, 0x1fa7425e, 0x73043362, 0x938b9824};

	BOOST_REQUIRE_EQUAL( digest.to_hex_string( ), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" );
	BOOST_REQUIRE( std::equal( digest.data.cbegin( ), digest.data.cend( ), expected_output.cbegin( ), expected_output.cend( ) ) );
}

BOOST_AUTO_TEST_CASE( sha256_003 ) {
	BOOST_REQUIRE_EQUAL( sha256( "Hello World" ), "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e" );
}

BOOST_AUTO_TEST_CASE( sha256_004 ) {
	BOOST_REQUIRE_EQUAL( sha256( "grape" ), "0f78fcc486f5315418fbf095e71c0675ee07d318e5ac4d150050cd8e57966496" );
}

BOOST_AUTO_TEST_CASE( sha256_005 ) {
	BOOST_REQUIRE_EQUAL( sha256( "How are you" ), "9c7d5b046878838da72e40ceb3179580958df544b240869b80d0275cc07209cc" );
}

BOOST_AUTO_TEST_CASE( sha256_007 ) {
	BOOST_REQUIRE_EQUAL( sha256( "1184CD2CDD640CA42CFC3A091C51D549B2F016D454B2774019C2B2D2E08529FD" ),
	                     "1c94d91f93ec9ed6bf647c384445b329c84a042c6b3832f8ee904dc55f117342" );
}

BOOST_AUTO_TEST_CASE( sha256_008 ) {
	BOOST_REQUIRE_EQUAL( sha256( "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" ),
	                     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" );
}

BOOST_AUTO_TEST_CASE( sha256_009 ) {
	BOOST_REQUIRE_EQUAL( sha256( "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmno"
	                             "pqrlmnopqrsmnopqrstnopqrstu" ),
	                     "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1" );
}

BOOST_AUTO_TEST_CASE( sha256_010 ) {
	std::string one_million_a;
	one_million_a.reserve( 1'000'000 );
	for( size_t n = 0; n < 1'000'000; ++n ) {
		one_million_a.push_back( 'a' );
	}
	BOOST_REQUIRE_EQUAL( sha256( one_million_a.data( ), one_million_a.size( ) ), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0" );
}

BOOST_AUTO_TEST_CASE( sha256_011 ) {
	std::string const msg{"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"};
	std::string tst;
	tst.reserve( msg.size( ) * 16'777'216 );
	for( size_t n = 0; n < 16'777'216; ++n ) {
		tst += msg;
	}
	BOOST_REQUIRE_EQUAL( sha256( tst.data( ), tst.size( ) ), "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e" );
}

