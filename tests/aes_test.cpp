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

#define BOOST_TEST_MODULE aes_test

#include <daw/boost_test.h>
#include <daw/daw_algorithm.h>

#include "aes.h"

using namespace daw::crypto;

using aes128_state_t = daw::static_array_t<uint8_t, 16>;

template<typename Container>
void show_state( Container const &c ) {
	for( size_t n = 0; n < 4; ++n ) {
		std::cout << std::hex << static_cast<int64_t>(c[n * 4]);
		for( size_t m = 1; m < 4; ++m ) {
			std::cout << ' ' << std::hex << static_cast<int64_t>(c[n * 4 + m]);
		}
		std::cout << '\n';
	}
}

template<typename Key, typename ExpectedOutput>
void test_key_schedule( Key const &key, ExpectedOutput const &expected_output ) {
	auto const key_sched = daw::crypto::aes::impl::aes128_key_schedule( daw::make_array_view( key ) );
	bool const result = daw::algorithm::equal( expected_output.cbegin( ), expected_output.cend( ), key_sched.cbegin( ),
	                                           key_sched.cend( ) );
	BOOST_REQUIRE( result );
}

BOOST_AUTO_TEST_CASE( aes_key_schedule_001 ) {
	using daw::crypto::aes::impl::AES128_KEY_SCHEDULE_SIZE;
	using daw::crypto::aes::impl::AES128_KEY_SIZE;

	// Test Data
	constexpr daw::static_array_t<uint8_t, AES128_KEY_SIZE::value> const input_01 = {
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	constexpr daw::static_array_t<uint8_t, AES128_KEY_SCHEDULE_SIZE::value> const expected_01 = {
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x63,
	    0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x9b, 0x98, 0x98, 0xc9,
	    0xf9, 0xfb, 0xfb, 0xaa, 0x9b, 0x98, 0x98, 0xc9, 0xf9, 0xfb, 0xfb, 0xaa, 0x90, 0x97, 0x34, 0x50, 0x69, 0x6c,
	    0xcf, 0xfa, 0xf2, 0xf4, 0x57, 0x33, 0x0b, 0x0f, 0xac, 0x99, 0xee, 0x06, 0xda, 0x7b, 0x87, 0x6a, 0x15, 0x81,
	    0x75, 0x9e, 0x42, 0xb2, 0x7e, 0x91, 0xee, 0x2b, 0x7f, 0x2e, 0x2b, 0x88, 0xf8, 0x44, 0x3e, 0x09, 0x8d, 0xda,
	    0x7c, 0xbb, 0xf3, 0x4b, 0x92, 0x90, 0xec, 0x61, 0x4b, 0x85, 0x14, 0x25, 0x75, 0x8c, 0x99, 0xff, 0x09, 0x37,
	    0x6a, 0xb4, 0x9b, 0xa7, 0x21, 0x75, 0x17, 0x87, 0x35, 0x50, 0x62, 0x0b, 0xac, 0xaf, 0x6b, 0x3c, 0xc6, 0x1b,
	    0xf0, 0x9b, 0x0e, 0xf9, 0x03, 0x33, 0x3b, 0xa9, 0x61, 0x38, 0x97, 0x06, 0x0a, 0x04, 0x51, 0x1d, 0xfa, 0x9f,
	    0xb1, 0xd4, 0xd8, 0xe2, 0x8a, 0x7d, 0xb9, 0xda, 0x1d, 0x7b, 0xb3, 0xde, 0x4c, 0x66, 0x49, 0x41, 0xb4, 0xef,
	    0x5b, 0xcb, 0x3e, 0x92, 0xe2, 0x11, 0x23, 0xe9, 0x51, 0xcf, 0x6f, 0x8f, 0x18, 0x8e};

	test_key_schedule( input_01, expected_01 );
}

BOOST_AUTO_TEST_CASE( aes_key_schedule_002 ) {
	using daw::crypto::aes::impl::AES128_KEY_SCHEDULE_SIZE;
	using daw::crypto::aes::impl::AES128_KEY_SIZE;

	// Test Data
	constexpr daw::static_array_t<uint8_t, AES128_KEY_SIZE::value> const input_02 = {
	    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	constexpr daw::static_array_t<uint8_t, AES128_KEY_SCHEDULE_SIZE::value> const expected_02 = {
	    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe8, 0xe9,
	    0xe9, 0xe9, 0x17, 0x16, 0x16, 0x16, 0xe8, 0xe9, 0xe9, 0xe9, 0x17, 0x16, 0x16, 0x16, 0xad, 0xae, 0xae, 0x19,
	    0xba, 0xb8, 0xb8, 0x0f, 0x52, 0x51, 0x51, 0xe6, 0x45, 0x47, 0x47, 0xf0, 0x09, 0x0e, 0x22, 0x77, 0xb3, 0xb6,
	    0x9a, 0x78, 0xe1, 0xe7, 0xcb, 0x9e, 0xa4, 0xa0, 0x8c, 0x6e, 0xe1, 0x6a, 0xbd, 0x3e, 0x52, 0xdc, 0x27, 0x46,
	    0xb3, 0x3b, 0xec, 0xd8, 0x17, 0x9b, 0x60, 0xb6, 0xe5, 0xba, 0xf3, 0xce, 0xb7, 0x66, 0xd4, 0x88, 0x04, 0x5d,
	    0x38, 0x50, 0x13, 0xc6, 0x58, 0xe6, 0x71, 0xd0, 0x7d, 0xb3, 0xc6, 0xb6, 0xa9, 0x3b, 0xc2, 0xeb, 0x91, 0x6b,
	    0xd1, 0x2d, 0xc9, 0x8d, 0xe9, 0x0d, 0x20, 0x8d, 0x2f, 0xbb, 0x89, 0xb6, 0xed, 0x50, 0x18, 0xdd, 0x3c, 0x7d,
	    0xd1, 0x50, 0x96, 0x33, 0x73, 0x66, 0xb9, 0x88, 0xfa, 0xd0, 0x54, 0xd8, 0xe2, 0x0d, 0x68, 0xa5, 0x33, 0x5d,
	    0x8b, 0xf0, 0x3f, 0x23, 0x32, 0x78, 0xc5, 0xf3, 0x66, 0xa0, 0x27, 0xfe, 0x0e, 0x05, 0x14, 0xa3, 0xd6, 0x0a,
	    0x35, 0x88, 0xe4, 0x72, 0xf0, 0x7b, 0x82, 0xd2, 0xd7, 0x85, 0x8c, 0xd7, 0xc3, 0x26};

	test_key_schedule( input_02, expected_02 );
}

BOOST_AUTO_TEST_CASE( aes_key_schedule_003 ) {
	using daw::crypto::aes::impl::AES128_KEY_SCHEDULE_SIZE;
	using daw::crypto::aes::impl::AES128_KEY_SIZE;

	// Test Data
	constexpr daw::static_array_t<uint8_t, AES128_KEY_SIZE::value> const input_03 = {
	    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

	constexpr daw::static_array_t<uint8_t, AES128_KEY_SCHEDULE_SIZE::value> const expected_03 = {
	    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xd6, 0xaa,
	    0x74, 0xfd, 0xd2, 0xaf, 0x72, 0xfa, 0xda, 0xa6, 0x78, 0xf1, 0xd6, 0xab, 0x76, 0xfe, 0xb6, 0x92, 0xcf, 0x0b,
	    0x64, 0x3d, 0xbd, 0xf1, 0xbe, 0x9b, 0xc5, 0x00, 0x68, 0x30, 0xb3, 0xfe, 0xb6, 0xff, 0x74, 0x4e, 0xd2, 0xc2,
	    0xc9, 0xbf, 0x6c, 0x59, 0x0c, 0xbf, 0x04, 0x69, 0xbf, 0x41, 0x47, 0xf7, 0xf7, 0xbc, 0x95, 0x35, 0x3e, 0x03,
	    0xf9, 0x6c, 0x32, 0xbc, 0xfd, 0x05, 0x8d, 0xfd, 0x3c, 0xaa, 0xa3, 0xe8, 0xa9, 0x9f, 0x9d, 0xeb, 0x50, 0xf3,
	    0xaf, 0x57, 0xad, 0xf6, 0x22, 0xaa, 0x5e, 0x39, 0x0f, 0x7d, 0xf7, 0xa6, 0x92, 0x96, 0xa7, 0x55, 0x3d, 0xc1,
	    0x0a, 0xa3, 0x1f, 0x6b, 0x14, 0xf9, 0x70, 0x1a, 0xe3, 0x5f, 0xe2, 0x8c, 0x44, 0x0a, 0xdf, 0x4d, 0x4e, 0xa9,
	    0xc0, 0x26, 0x47, 0x43, 0x87, 0x35, 0xa4, 0x1c, 0x65, 0xb9, 0xe0, 0x16, 0xba, 0xf4, 0xae, 0xbf, 0x7a, 0xd2,
	    0x54, 0x99, 0x32, 0xd1, 0xf0, 0x85, 0x57, 0x68, 0x10, 0x93, 0xed, 0x9c, 0xbe, 0x2c, 0x97, 0x4e, 0x13, 0x11,
	    0x1d, 0x7f, 0xe3, 0x94, 0x4a, 0x17, 0xf3, 0x07, 0xa7, 0x8b, 0x4d, 0x2b, 0x30, 0xc5,
	};

	test_key_schedule( input_03, expected_03 );
}

BOOST_AUTO_TEST_CASE( aes_key_schedule_004 ) {
	using daw::crypto::aes::impl::AES128_KEY_SCHEDULE_SIZE;
	using daw::crypto::aes::impl::AES128_KEY_SIZE;

	// Test Data
	constexpr daw::static_array_t<uint8_t, AES128_KEY_SIZE::value> const input_04 = {
	    0x69, 0x20, 0xe2, 0x99, 0xa5, 0x20, 0x2a, 0x6d, 0x65, 0x6e, 0x63, 0x68, 0x69, 0x74, 0x6f, 0x2a};

	constexpr daw::static_array_t<uint8_t, AES128_KEY_SCHEDULE_SIZE::value> const expected_04 = {
	    0x69, 0x20, 0xe2, 0x99, 0xa5, 0x20, 0x2a, 0x6d, 0x65, 0x6e, 0x63, 0x68, 0x69, 0x74, 0x6f, 0x2a, 0xfa, 0x88,
	    0x07, 0x60, 0x5f, 0xa8, 0x2d, 0x0d, 0x3a, 0xc6, 0x4e, 0x65, 0x53, 0xb2, 0x21, 0x4f, 0xcf, 0x75, 0x83, 0x8d,
	    0x90, 0xdd, 0xae, 0x80, 0xaa, 0x1b, 0xe0, 0xe5, 0xf9, 0xa9, 0xc1, 0xaa, 0x18, 0x0d, 0x2f, 0x14, 0x88, 0xd0,
	    0x81, 0x94, 0x22, 0xcb, 0x61, 0x71, 0xdb, 0x62, 0xa0, 0xdb, 0xba, 0xed, 0x96, 0xad, 0x32, 0x3d, 0x17, 0x39,
	    0x10, 0xf6, 0x76, 0x48, 0xcb, 0x94, 0xd6, 0x93, 0x88, 0x1b, 0x4a, 0xb2, 0xba, 0x26, 0x5d, 0x8b, 0xaa, 0xd0,
	    0x2b, 0xc3, 0x61, 0x44, 0xfd, 0x50, 0xb3, 0x4f, 0x19, 0x5d, 0x09, 0x69, 0x44, 0xd6, 0xa3, 0xb9, 0x6f, 0x15,
	    0xc2, 0xfd, 0x92, 0x45, 0xa7, 0x00, 0x77, 0x78, 0xae, 0x69, 0x33, 0xae, 0x0d, 0xd0, 0x5c, 0xbb, 0xcf, 0x2d,
	    0xce, 0xfe, 0xff, 0x8b, 0xcc, 0xf2, 0x51, 0xe2, 0xff, 0x5c, 0x5c, 0x32, 0xa3, 0xe7, 0x93, 0x1f, 0x6d, 0x19,
	    0x24, 0xb7, 0x18, 0x2e, 0x75, 0x55, 0xe7, 0x72, 0x29, 0x67, 0x44, 0x95, 0xba, 0x78, 0x29, 0x8c, 0xae, 0x12,
	    0x7c, 0xda, 0xdb, 0x47, 0x9b, 0xa8, 0xf2, 0x20, 0xdf, 0x3d, 0x48, 0x58, 0xf6, 0xb1};

	test_key_schedule( input_04, expected_04 );
}

BOOST_AUTO_TEST_CASE( aes_round_key_001 ) {
	constexpr aes128_state_t const input_01 = {0x0,  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	                                           0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

	constexpr aes128_state_t const key_01 = {0x0,  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

	constexpr aes128_state_t const expected_01 = {0x0,  0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
	                                              0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0};

	auto const test = []( auto input, auto const &key, auto const &expected_out ) {
		daw::crypto::aes::impl::aes_add_round_key( daw::make_span( input ), daw::make_array_view( key ) );
		auto const result =
		    daw::algorithm::equal( input.cbegin( ), input.cend( ), expected_out.cbegin( ), expected_out.cend( ) );
		BOOST_REQUIRE( result );
	};

	test( input_01, key_01, expected_01 );
}

BOOST_AUTO_TEST_CASE( aes_sbox_001 ) {
	constexpr aes128_state_t const input_01 = {0x8e, 0x9f, 0xf1, 0xc6, 0x4d, 0xdc, 0xe1, 0xc7,
	                                           0xa1, 0x58, 0xd1, 0xc8, 0xbc, 0x9d, 0xc1, 0xc9};

	constexpr aes128_state_t const expected_01 = {0x19, 0xdb, 0xa1, 0xb4, 0xe3, 0x86, 0xf8, 0xc6,
	                                              0x32, 0x6a, 0x3e, 0xe8, 0x65, 0x5e, 0x78, 0xdd};

	auto const test = []( auto const &input, auto const &expected_out ) {
		for( size_t n = 0; n < input.size( ); ++n ) {
			auto const output = daw::crypto::aes::impl::aes_sbox( input[n] );
			bool const result = output == expected_out[n];
			BOOST_REQUIRE( result );
		}
	};

	test( input_01, expected_01 );
}

template<typename Input, typename ExpectedOut>
void test_add_subbytes( Input input, ExpectedOut const &expected_out ) {
	daw::crypto::aes::impl::aes_sub_bytes( daw::make_span( input ) );
	auto const result =
	    daw::algorithm::equal( input.cbegin( ), input.cend( ), expected_out.cbegin( ), expected_out.cend( ) );

	BOOST_REQUIRE( result );
}

BOOST_AUTO_TEST_CASE( aes_add_subbytes_001 ) {
	constexpr aes128_state_t const input_01 = {0x8e, 0x9f, 0xf1, 0xc6, 0x4d, 0xdc, 0xe1, 0xc7,
	                                           0xa1, 0x58, 0xd1, 0xc8, 0xbc, 0x9d, 0xc1, 0xc9};

	constexpr aes128_state_t const expected_01 = {0x19, 0xdb, 0xa1, 0xb4, 0xe3, 0x86, 0xf8, 0xc6,
	                                              0x32, 0x6a, 0x3e, 0xe8, 0x65, 0x5e, 0x78, 0xdd};

	test_add_subbytes( input_01, expected_01 );
}

BOOST_AUTO_TEST_CASE( aes_add_subbytes_002 ) {
	constexpr aes128_state_t const input_02 = {0x0,  0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
	                                           0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0};

	constexpr aes128_state_t const expected_02 = {0x63, 0xca, 0xb7, 0x04, 0x09, 0x53, 0xd0, 0x51,
	                                              0xcd, 0x60, 0xe0, 0xe7, 0xba, 0x70, 0xe1, 0x8c};

	test_add_subbytes( input_02, expected_02 );
}

BOOST_AUTO_TEST_CASE( aes_shift_rows_001 ) {
	constexpr aes128_state_t const input_01 = {0x8e, 0x9f, 0x01, 0xc6, 0x4d, 0xdc, 0x01, 0xc6,
	                                           0xa1, 0x58, 0x01, 0xc6, 0xbc, 0x9d, 0x01, 0xc6};

	constexpr aes128_state_t const expected_01 = {0x8e, 0x9f, 0x01, 0xc6, 0xdc, 0x01, 0xc6, 0x4d,
	                                              0x01, 0xc6, 0xa1, 0x58, 0xc6, 0xbc, 0x9d, 0x01};

	auto const test = []( auto input, auto const &expected_out ) {
		daw::crypto::aes::impl::aes_shift_rows( daw::make_span( input ) );
		bool const result = input == expected_out;
		BOOST_REQUIRE( result );
	};

	test( input_01, expected_01 );
	//	test( input_02, expected_02 );
}

BOOST_AUTO_TEST_CASE( aes_mix_columns_001 ) {
	constexpr aes128_state_t const input_01 = {0xdb, 0xf2, 0x01, 0xc6, 0x13, 0x0a, 0x01, 0xc6,
	                                           0x53, 0x22, 0x01, 0xc6, 0x45, 0x5c, 0x01, 0xc6};

	constexpr aes128_state_t const expected_01 = {0x8e, 0x9f, 0x01, 0xc6, 0x4d, 0xdc, 0x01, 0xc6,
	                                              0xa1, 0x58, 0x01, 0xc6, 0xbc, 0x9d, 0x01, 0xc6};

	auto const test = []( auto input, auto const &expected_out ) {
		daw::crypto::aes::impl::aes_mix_columns( daw::make_span( input ) );
		bool const result = input == expected_out;
		//BOOST_REQUIRE( result );
	};

	test( input_01, expected_01 );
}

template<typename Key, typename Input, typename ExpectedOut>
void test_enc_dec( Key const &key, Input const &input, ExpectedOut const &expected_out ) {
	auto const enc_output =
	    daw::crypto::aes::impl::aes_encrypt_128_block( daw::make_array_view( input ), daw::make_array_view( key ) );

	auto const deciphered_input = daw::crypto::aes::impl::aes_decrypt_128_block( daw::make_array_view( enc_output ),
	                                                                             daw::make_array_view( key ) );

	auto const dec_output = daw::crypto::aes::impl::aes_decrypt_128_block( daw::make_array_view( expected_out ),
	                                                                       daw::make_array_view( key ) );

	bool const enc_match =
	    daw::algorithm::equal( enc_output.cbegin( ), enc_output.cend( ), expected_out.cbegin( ), expected_out.cend( ) );

	bool const dec_match =
	    daw::algorithm::equal( dec_output.cbegin( ), dec_output.cend( ), input.cbegin( ), input.cend( ) );

	bool const encdec_match =
	    daw::algorithm::equal( deciphered_input.cbegin( ), deciphered_input.cend( ), input.cbegin( ), input.cend( ) );

	std::cout << "cipher:\n";
	show_state( enc_output );
	std::cout << "expected:\n";
	show_state( expected_out );

	BOOST_REQUIRE_MESSAGE( encdec_match, "Round trip failed dec( enc( input ) ) != input" );
	BOOST_REQUIRE_MESSAGE( enc_match, "Wrong cipher on enc( input )" );
	BOOST_REQUIRE_MESSAGE( dec_match, "Wrong input on dec( cipher )" );
}

BOOST_AUTO_TEST_CASE( aes_encrypt_decrypt_001 ) {
	constexpr aes128_state_t const key_01 = {0x2b, 0x7e, 0x15, 0x16,
											 0x28, 0xae, 0xd2, 0xa6,
	                                         0xab, 0xf7, 0x15, 0x88,
											 0x09, 0xcf, 0x4f, 0x3c};

	constexpr aes128_state_t const input_01 = {0x32, 0x43, 0xf6, 0xa8,
											   0x88, 0x5a, 0x30, 0x8d,
	                                           0x31, 0x31, 0x98, 0xa2,
											   0xe0, 0x37, 0x07, 0x34};

	constexpr aes128_state_t const expected_01 = {0x39, 0x02, 0xdc, 0x19,
												  0x25, 0xdc, 0x11, 0x6a,
	                                              0x84, 0x09, 0x85, 0x0b,
												  0x1d, 0xfb, 0x97, 0x32};

	test_enc_dec( key_01, input_01, expected_01 );
}

BOOST_AUTO_TEST_CASE( aes_encrypt_decrypt_002 ) {
	constexpr aes128_state_t const key_02 = {0x2b, 0x7e, 0x15, 0x16,
											 0x28, 0xae, 0xd2, 0xa6,
	                                         0xab, 0xf7, 0x15, 0x88,
											 0x09, 0xcf, 0x4f, 0x3c};

	constexpr aes128_state_t const input_02 = {0x6b, 0xc1, 0xbe, 0xe2,
											   0x2e, 0x40, 0x9f, 0x96,
	                                           0xe9, 0x3d, 0x7e, 0x11,
											   0x73, 0x93, 0x17, 0x2a};

	constexpr aes128_state_t const expected_02 = {0x76, 0x49, 0xab, 0xac,
												  0x81, 0x19, 0xb2, 0x46,
	                                              0xce, 0xe9, 0x8e, 0x9b,
												  0x12, 0xe9, 0x19, 0x7d};

	test_enc_dec( key_02, input_02, expected_02 );
}

BOOST_AUTO_TEST_CASE( aes_encrypt_decrypt_003 ) {
	constexpr aes128_state_t const key_03 = {0x0,  0x01, 0x02, 0x03,
											 0x04, 0x05, 0x06, 0x07,
	                                         0x08, 0x09, 0x0a, 0x0b,
											 0x0c, 0x0d, 0x0e, 0x0f};

	constexpr aes128_state_t const input_03 = {0x0,  0x11, 0x22, 0x33,
											   0x44, 0x55, 0x66, 0x77,
	                                           0x88, 0x99, 0xaa, 0xbb,
											   0xcc, 0xdd, 0xee, 0xff};

	constexpr aes128_state_t const expected_03 = {0x69, 0xc4, 0xe0, 0xd8,
												  0x6a, 0x7b, 0x04, 0x30,
	                                              0xd8, 0xcd, 0xb7, 0x80,
												  0x70, 0xb4, 0xc5, 0x5a};

	test_enc_dec( key_03, input_03, expected_03 );
}

