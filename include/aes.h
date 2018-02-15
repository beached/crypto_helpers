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

#pragma once

#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <type_traits>

#include <daw/daw_algorithm.h>
#include <daw/daw_array_view.h>
#include <daw/daw_fixed_stack.h>
#include <daw/daw_iterator.h>
#include <daw/daw_span.h>
#include <daw/daw_string_view.h>

namespace daw {
	namespace crypto {
		namespace aes {
			namespace impl {
				using AES_BLOCK_SIZE = std::integral_constant<uint8_t, 16u>;
				using AES_COLUMN_SIZE = std::integral_constant<uint8_t, 4u>;
				using AES_KEY_SCHEDULE_WORD_SIZE = std::integral_constant<uint8_t, 4u>;
				using AES_NUM_COLUMNS = std::integral_constant<uint8_t, 4u>;

				using AES128_NUM_ROUNDS = std::integral_constant<uint8_t, 10u>;

				using AES128_KEY_SCHEDULE_SIZE =
				    std::integral_constant<uint8_t, AES_BLOCK_SIZE::value *( AES128_NUM_ROUNDS::value + 1u )>;

				using AES128_KEY_SIZE = std::integral_constant<uint8_t, 16u>;
			} // namespace impl

			using cipher_t = daw::static_array_t<uint8_t, 16>;

			template<size_t KeyScheduleSize>
			using key_schedule_t = daw::static_array_t<uint8_t, KeyScheduleSize>;

			using aes128_key_schedule_t = key_schedule_t<impl::AES128_KEY_SCHEDULE_SIZE::value>;

			namespace impl {
				constexpr uint8_t aes_rotate_left_uint8( uint8_t a, uint_fast8_t num_bits ) noexcept {
					return static_cast<uint8_t>( ( a << num_bits ) | ( a >> ( 8u - num_bits ) ) );
				}

				constexpr uint8_t aes_mul2( uint8_t a ) noexcept {
					uint8_t const AES_REDUCE_BYTE = 0x1B;
					return static_cast<uint8_t>( ( a << 1u ) ^ ( ( -( a >= 0x80u ) ) & AES_REDUCE_BYTE ) );
				}

				constexpr uint8_t aes_mul( uint8_t a, uint8_t b ) noexcept {
					uint8_t result = 0;
					for( uint_fast8_t i = 0; i < 8u; i++ ) {
						result ^= ( -( b & 1u ) ) & a;
						a = aes_mul2( a );
						b >>= 1;
					}
					return result;
				}

				constexpr uint8_t aes_inv( uint8_t a ) noexcept {
					uint8_t const CHAIN_LEN = 11u;
					daw::static_array_t<uint8_t, CHAIN_LEN> addition_chain_idx = {0, 1, 1, 3, 4, 3, 6, 7, 3, 9, 1};
					daw::static_array_t<uint8_t, CHAIN_LEN> prev_values{0};

					for( uint_fast8_t i = 0; i < addition_chain_idx.size( ); ++i ) {
						prev_values[i] = a;
						a = aes_mul( a, prev_values[addition_chain_idx[i]] );
					}
					return a;
				}

				constexpr uint8_t aes_sbox( uint8_t a ) noexcept {
					a = aes_inv( a );
					auto x = aes_rotate_left_uint8( a, 1u );
					x ^= aes_rotate_left_uint8( x, 1u );
					x ^= aes_rotate_left_uint8( x, 2u );

					return static_cast<uint8_t>( a ^ x ^ 0x63u );
				}

				constexpr void aes_sub_bytes( daw::span<uint8_t> block ) noexcept {
					for( uint_fast8_t n = 0; n < AES_BLOCK_SIZE::value; ++n ) {
						block[n] = aes_sbox( block[n] );
					}
				}

				constexpr uint8_t aes_sbox_inv( uint8_t a ) noexcept {
					auto x = aes_rotate_left_uint8( a, 1u );
					a = aes_rotate_left_uint8( x, 2u );
					x ^= a;
					a = aes_rotate_left_uint8( a, 3u );

					return aes_inv( static_cast<uint8_t>( a ^ x ^ 0x05u ) );
				}

				constexpr void aes_sbox_inv_apply_block( daw::span<uint8_t> p_block ) noexcept {
					for( auto &val : p_block ) {
						val = aes_sbox_inv( val );
					}
				}

				constexpr void aes_add_round_key( daw::span<uint8_t> message, daw::array_view<uint8_t> key ) noexcept {
					for( uint_fast8_t n = 0; n < AES_BLOCK_SIZE::value; ++n ) {
						message[n] ^= key[n];
					}
				}

				constexpr void aes_shift_rows( daw::span<uint8_t> block ) noexcept {
					// Rotate each item left by n for each row
					for( int_fast8_t n = 1; n < AES_NUM_COLUMNS::value; ++n ) {
						auto cur_block =
						    block.subset( static_cast<uint8_t>( AES_COLUMN_SIZE::value * n ), AES_COLUMN_SIZE::value );
						daw::algorithm::rotate( cur_block.begin( ), daw::next( cur_block.begin( ), n ),
						                        cur_block.end( ) );
					}
				}

				constexpr void aes_shift_rows_inv( daw::span<uint8_t> block ) noexcept {
					// Rotate each item right by n for each row
					for( uint_fast8_t n = 1; n < AES_NUM_COLUMNS::value; ++n ) {
						auto cur_block = block.subset( AES_COLUMN_SIZE::value * n, AES_COLUMN_SIZE::value );
						daw::algorithm::rotate( cur_block.rbegin( ), daw::next( cur_block.rbegin( ), n ),
						                        cur_block.rend( ) );
					}
				}

				constexpr uint8_t blk_pos( uint8_t r, uint8_t c ) noexcept {
					return r * AES_COLUMN_SIZE::value + c;
				}

				constexpr void aes_mix_columns( daw::span<uint8_t> block ) noexcept {
					for( uint_fast8_t n = 0; n < AES_NUM_COLUMNS::value; ++n ) {
						daw::static_array_t<uint8_t, AES_COLUMN_SIZE::value> temp_column{
						    static_cast<uint8_t>( aes_mul( block[blk_pos( 0, n )], 2u ) ^
						                          aes_mul( block[blk_pos( 1, n )], 3u ) ^ block[blk_pos( 2, n )] ^
						                          block[blk_pos( 3, n )] ),

						    static_cast<uint8_t>( block[blk_pos( 0, n )] ^ aes_mul( block[blk_pos( 1, n )], 2u ) ^
						                          aes_mul( block[blk_pos( 2, n )], 3u ) ^ block[blk_pos( 3, n )] ),

						    static_cast<uint8_t>( block[blk_pos( 0, n )] ^ block[blk_pos( 1, n )] ^
						                          aes_mul( block[blk_pos( 2, n )], 2u ) ^
						                          aes_mul( block[blk_pos( 3, n )], 3u ) ),

						    static_cast<uint8_t>( aes_mul( block[blk_pos( 0, n )], 3u ) ^ block[blk_pos( 1, n )] ^
						                          block[blk_pos( 2, n )] ^ aes_mul( block[blk_pos( 3, n )], 2u ) ),
						};
						block[blk_pos( 0, n )] = temp_column[0];
						block[blk_pos( 1, n )] = temp_column[1];
						block[blk_pos( 2, n )] = temp_column[2];
						block[blk_pos( 3, n )] = temp_column[3];
					}
				}

				constexpr void aes_mix_columns_inv( daw::span<uint8_t> block ) noexcept {
					for( uint_fast8_t n = 0; n < AES_NUM_COLUMNS::value; ++n ) {
						daw::static_array_t<uint8_t, AES_COLUMN_SIZE::value> temp_column{
						    static_cast<uint8_t>(
						        aes_mul( block[blk_pos( 0, n )], 14u ) ^ aes_mul( block[blk_pos( 1, n )], 11u ) ^
						        aes_mul( block[blk_pos( 2, n )], 13u ) ^ aes_mul( block[blk_pos( 3, n )], 9u ) ),

						    static_cast<uint8_t>(
						        aes_mul( block[blk_pos( 0, n )], 9u ) ^ aes_mul( block[blk_pos( 1, n )], 14u ) ^
						        aes_mul( block[blk_pos( 2, n )], 11u ) ^ aes_mul( block[blk_pos( 3, n )], 13u ) ),

						    static_cast<uint8_t>(
						        aes_mul( block[blk_pos( 0, n )], 13u ) ^ aes_mul( block[blk_pos( 1, n )], 9u ) ^
						        aes_mul( block[blk_pos( 2, n )], 14u ) ^ aes_mul( block[blk_pos( 3, n )], 11u ) ),

						    static_cast<uint8_t>(
						        aes_mul( block[blk_pos( 0, n )], 11u ) ^ aes_mul( block[blk_pos( 1, n )], 13u ) ^
						        aes_mul( block[blk_pos( 2, n )], 9u ) ^ aes_mul( block[blk_pos( 3, n )], 14u ) ),
						};
						block[blk_pos( 0, n )] = temp_column[0];
						block[blk_pos( 1, n )] = temp_column[1];
						block[blk_pos( 2, n )] = temp_column[2];
						block[blk_pos( 3, n )] = temp_column[3];
					}
				}

				constexpr aes128_key_schedule_t aes128_key_schedule( daw::array_view<uint8_t> key ) {
					uint8_t const AES_KEY_SCHEDULE_FIRST_RCON = 1u;
					auto rcon = AES_KEY_SCHEDULE_FIRST_RCON;

					/* Initial part of key schedule is simply the AES-128 key copied verbatim. */
					aes128_key_schedule_t result{0};

					daw::algorithm::copy( key.cbegin( ), key.cend( ), result.begin( ) );

					uint8_t const tot_rounds = ( AES128_KEY_SCHEDULE_SIZE::value - AES128_KEY_SIZE::value ) /
					                           AES_KEY_SCHEDULE_WORD_SIZE::value;

					auto p_key_0 = make_span( result, AES128_KEY_SIZE::value );

					for( uint_fast8_t round = 0; round < tot_rounds; ++round ) {

						daw::algorithm::copy_n( p_key_0.data( ) - AES_KEY_SCHEDULE_WORD_SIZE::value, p_key_0.begin( ),
						                        AES_KEY_SCHEDULE_WORD_SIZE::value );

						if( ( round % ( AES128_KEY_SIZE::value / AES_KEY_SCHEDULE_WORD_SIZE::value ) ) == 0 ) {
							/* Rotate previous word and apply S-box. Also XOR Rcon for first byte. */
							auto const temp_byte = p_key_0[0];
							p_key_0[0] = aes_sbox( p_key_0[1] ) ^ rcon;
							p_key_0[1] = aes_sbox( p_key_0[2] );
							p_key_0[2] = aes_sbox( p_key_0[3] );
							p_key_0[3] = aes_sbox( temp_byte );

							/* Next rcon */
							rcon = aes_mul2( rcon );
						}

						/* XOR in bytes from AES128_KEY_SIZE::value bytes ago */
						p_key_0[0] ^= p_key_0.data( )[0 - static_cast<int>( AES128_KEY_SIZE::value )];
						p_key_0[1] ^= p_key_0.data( )[1 - static_cast<int>( AES128_KEY_SIZE::value )];
						p_key_0[2] ^= p_key_0.data( )[2 - static_cast<int>( AES128_KEY_SIZE::value )];
						p_key_0[3] ^= p_key_0.data( )[3 - static_cast<int>( AES128_KEY_SIZE::value )];

						p_key_0.remove_prefix( AES_KEY_SCHEDULE_WORD_SIZE::value );
					}
					return result;
				}

				constexpr cipher_t convert_state( daw::array_view<uint8_t> const &msg ) noexcept {
					return cipher_t{msg[0], msg[4], msg[8],  msg[12], msg[1], msg[5], msg[9],  msg[13],
					                msg[2], msg[6], msg[10], msg[14], msg[3], msg[7], msg[11], msg[15]};
				}

				/// @brief Encrypt a block of uint8_t's.
				constexpr cipher_t aes_encrypt_128_block( daw::array_view<uint8_t> input,
				                                          daw::array_view<uint8_t> key ) noexcept {

					auto const key_sched = impl::aes128_key_schedule( key );
					auto result = convert_state( input );
					auto state = make_span( result );

					auto key_round = make_array_view( key_sched );
					impl::aes_add_round_key( state, key_round );

					for( uint_fast8_t round = 1; round < AES128_NUM_ROUNDS::value; ++round ) {
						impl::aes_sub_bytes( state );
						impl::aes_shift_rows( state );
						impl::aes_mix_columns( state );

						key_round.remove_prefix( AES_BLOCK_SIZE::value );
						impl::aes_add_round_key( state, key_round );
					}
					impl::aes_sub_bytes( state );
					impl::aes_shift_rows( state );

					key_round.remove_prefix( AES_BLOCK_SIZE::value );
					impl::aes_add_round_key( state, key_round );

					return result;
					// return convert_state( make_array_view( result ) );
				}

				constexpr cipher_t aes_decrypt_128_block( daw::array_view<uint8_t> input,
				                                          daw::array_view<uint8_t> key ) noexcept {

					auto const key_sched = impl::aes128_key_schedule( key );
					cipher_t result{0};
					daw::algorithm::copy( input.cbegin( ), input.cend( ), result.begin( ) );
					auto state = make_span( result );

					auto key_round = daw::make_array_view( key_sched, AES128_NUM_ROUNDS::value * AES_BLOCK_SIZE::value,
					                                       AES_BLOCK_SIZE::value );
					impl::aes_add_round_key( state, key_round );

					impl::aes_shift_rows_inv( state );
					impl::aes_sbox_inv_apply_block( state );

					for( uint_fast8_t round = AES128_NUM_ROUNDS::value - 1u; round > 0; --round ) {
						key_round =
						    daw::make_array_view( key_sched, round * AES_BLOCK_SIZE::value, AES_BLOCK_SIZE::value );
						impl::aes_add_round_key( state, key_round );

						impl::aes_mix_columns_inv( state );
						impl::aes_shift_rows_inv( state );
						impl::aes_sbox_inv_apply_block( state );
					}

					key_round = daw::make_array_view( key_sched, 0, AES_BLOCK_SIZE::value );
					impl::aes_add_round_key( state, key_round );

					// return result;
					return convert_state( make_array_view( result ) );
				}

				constexpr void aes_encrypt_128_block( daw::array_view<uint8_t> input, daw::array_view<uint8_t> key,
				                                      daw::span<uint8_t> cipher ) noexcept {
					auto const tmp = aes_encrypt_128_block( input.subset( 0, AES_BLOCK_SIZE::value ), key );
					daw::algorithm::copy( tmp.cbegin( ), tmp.cend( ), cipher.begin( ) );
				}

			} // namespace impl

			// cipher must have enough room for round(input.size( )/AES_BLOCK_SIZE::value) * AES_BLOCK_SIZE::value
			constexpr void aes_encrypt_128( daw::array_view<uint8_t> input, daw::array_view<uint8_t> key,
			                                daw::span<uint8_t> cipher ) noexcept {
				size_t const count = input.size( ) / impl::AES_BLOCK_SIZE::value;
				for( size_t n = 0; n < count; ++n ) {
					impl::aes_encrypt_128_block( input.subset( 0, impl::AES_BLOCK_SIZE::value ), key, cipher );
					input.remove_prefix( impl::AES_BLOCK_SIZE::value );
					cipher.remove_prefix( impl::AES_BLOCK_SIZE::value );
				}
				if( !input.empty( ) ) {
					daw::static_array_t<uint8_t, impl::AES_BLOCK_SIZE::value> ct_tmp{0};
					daw::algorithm::copy( input.cbegin( ), input.cend( ), ct_tmp.begin( ) );
					impl::aes_encrypt_128_block( daw::make_array_view( ct_tmp ), key, cipher );
				}
			} // namespace aes
		}     // namespace aes
	}         // namespace crypto
} // namespace daw

