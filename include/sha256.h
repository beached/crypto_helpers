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

#include <daw/daw_array_view.h>
#include <daw/daw_fixed_stack.h>
#include <daw/daw_stack_array.h>
#include <daw/daw_string_view.h>

namespace daw {
	namespace crypto {
		namespace impl {
			template<size_t bits, typename word_t>
			constexpr auto SHA2_SHFR( word_t const x) noexcept {
				static_assert( bits <= sizeof( word_t )*8, "Cannot shift more than word size bits" );
				return x >> bits;
			}

			template<size_t bits, typename word_t>
			constexpr auto SHA2_ROTR( word_t const x ) noexcept {
				static_assert( bits <= sizeof( word_t )*8, "Cannot shift more than word size bits" );
				return ( x >> bits ) | ( x << ( ( sizeof( word_t ) * 8 ) - bits ) );
			}

			template<typename word_t>
			constexpr auto SHA2_CH( word_t const x, word_t const y, word_t const z ) noexcept {
				return ( x & y ) ^ ( ~x & z );
			}

			template<typename word_t>
			constexpr auto SHA2_MAJ( word_t const x, word_t const y, word_t const z ) noexcept {
				return ( x & y ) ^ ( x & z ) ^ ( y & z );
			}

			template<typename word_t>
			constexpr auto SHA256_F1( word_t const x ) noexcept {
				return SHA2_ROTR<2u>( x ) ^ SHA2_ROTR<13u>( x ) ^ SHA2_ROTR<22u>( x );
			}

			template<typename word_t>
			constexpr auto SHA256_F2( word_t const x ) noexcept {
				return SHA2_ROTR<6u>( x ) ^ SHA2_ROTR<11u>( x ) ^ SHA2_ROTR<25u>( x );
			}

			template<typename word_t>
			constexpr auto SHA256_F3( word_t const x ) noexcept {
				return SHA2_ROTR<7u>( x ) ^ SHA2_ROTR<18u>( x ) ^ SHA2_SHFR<3u>( x );
			}

			template<typename word_t>
			constexpr auto SHA256_F4( word_t const x ) noexcept {
				return SHA2_ROTR<17u>( x ) ^ SHA2_ROTR<19u>( x ) ^ SHA2_SHFR<10u>( x );
			}

			constexpr void SHA2_UNPACK32( uint32_t const x, uint8_t *str ) noexcept {
				str[3] = static_cast<uint8_t>( x );
				str[2] = static_cast<uint8_t>( x >> 8u );
				str[1] = static_cast<uint8_t>( x >> 16u );
				str[0] = static_cast<uint8_t>( x >> 24u );
			}

			constexpr void SHA2_PACK32( uint8_t const *str, uint32_t & x ) noexcept {
				x = static_cast<uint32_t>( str[3] ) | static_cast<uint32_t>( str[2] << 8u ) |
				    static_cast<uint32_t>( str[1] << 16u ) | static_cast<uint32_t>( str[0] << 24u );
			}

			constexpr uint8_t to_nibble( uint8_t c ) noexcept {
				c &= 0x0F;
				if( c < 10 ) {
					return '0' + c;
				}
				return 'a' + ( c - 10 );
			}

			constexpr uint16_t to_hex( uint8_t c ) noexcept {
				auto result = static_cast<uint16_t>( to_nibble( c >> 4u ) << 8u );
				result |= to_nibble( c );
				return result;
			}
		} // namespace impl

		template<size_t digest_size>
		struct digest_t {
			using value_t = uint8_t;
			using reference = value_t &;
			using const_reference = value_t const &;
			using iterator = value_t *;
			using const_iterator = value_t const *;
			daw::array_t<value_t, digest_size> m_data;

			constexpr digest_t( ) noexcept : m_data{0} {}

			std::string to_hex_string( ) const {
				std::stringstream ss;
				for( auto const c : m_data ) {
					auto as_hex = impl::to_hex( c );
					ss << static_cast<char>( ( as_hex & 0xFF00 ) >> 8 ) << static_cast<char>( as_hex & 0x00FF );
				}
				return ss.str( );
			}

			constexpr size_t size( ) const noexcept {
				return m_data.size( );
			}

			constexpr reference operator[]( size_t pos ) noexcept {
				return m_data[pos];
			}

			constexpr const_reference operator[]( size_t pos ) const noexcept {
				return m_data[pos];
			}

			constexpr iterator data( ) noexcept {
				return m_data.data( );
			}

			constexpr iterator begin( ) noexcept {
				return m_data.begin( );
			}

			constexpr iterator end( ) noexcept {
				return m_data.end( );
			}

			constexpr const_iterator data( ) const noexcept {
				return m_data.data( );
			}

			constexpr const_iterator begin( ) const noexcept {
				return m_data.begin( );
			}

			constexpr const_iterator cbegin( ) const noexcept {
				return m_data.cbegin( );
			}

			constexpr const_iterator end( ) const noexcept {
				return m_data.end( );
			}

			constexpr const_iterator cend( ) const noexcept {
				return m_data.cend( );
			}
		};
		using sha256_digest_t = digest_t<256/8>;

		template<size_t digest_size, typename>
		struct sha2_ctx;

		template<typename T>
		struct sha2_ctx<256, T> {
			using word_t = uint32_t;
			using byte_t = uint8_t;
			static constexpr size_t const block_size = ( 512 / 8 );  // 512 bits
			static constexpr size_t const digest_size = ( 256 / 8 ); // 256 bits

		  private:
			size_t m_tot_len;
			size_t m_len;
//			daw::array_t<byte_t, 2*block_size> m_block;
			daw::fixed_stack_t<byte_t, 2*block_size> m_block;
			daw::array_t<word_t, 8> m_h;

			constexpr void transform( byte_t const *message, size_t const block_nb ) noexcept {
				/*
				 * Initialize array of round constants:
				 * (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
				 */
				daw::array_t<word_t, 64> const sha256_k{
				    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
				    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
				    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
				    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
				    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
				    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
				    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
				    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

				daw::array_t<word_t, 64> w = {0};
				daw::array_t<word_t, 8> wv = {0};
				word_t t1 = 0;
				word_t t2 = 0;

				byte_t const *sub_block = nullptr;

				for( size_t i = 0; i < block_nb; i++ ) {
					sub_block = message + ( i * 64u);
					for( size_t j = 0; j < 16; j++ ) {
						impl::SHA2_PACK32( &sub_block[j * 4u], w[j] );
					}
					for( size_t j = 16; j < 64; j++ ) {
						w[j] = impl::SHA256_F4( w[j - 2] ) + w[j - 7] + impl::SHA256_F3( w[j - 15] ) + w[j - 16];
					}
					for( size_t j = 0; j < 8; j++ ) {
						wv[j] = m_h[j];
					}
					for( size_t j = 0; j < 64; j++ ) {
						t1 = wv[7] + impl::SHA256_F2( wv[4] ) + impl::SHA2_CH( wv[4], wv[5], wv[6] ) + sha256_k[j] +
						     w[j];
						t2 = impl::SHA256_F1( wv[0] ) + impl::SHA2_MAJ( wv[0], wv[1], wv[2] );
						wv[7] = wv[6];
						wv[6] = wv[5];
						wv[5] = wv[4];
						wv[4] = wv[3] + t1;
						wv[3] = wv[2];
						wv[2] = wv[1];
						wv[1] = wv[0];
						wv[0] = t1 + t2;
					}
					for( size_t j = 0; j < 8; j++ ) {
						m_h[j] += wv[j];
					}
				}
			}

			template<typename U, size_t N>
			constexpr void transform( daw::array_t<U, N> const &message, size_t const block_nb ) noexcept {
				return transform( message.data( ), block_nb );
			}

			template<typename Iterator1, typename Iterator2>
			constexpr void copy_values( Iterator1 first_in, size_t count, Iterator2 first_out ) noexcept {
				for( size_t n=0; n<count; ++n ) {
					*first_out++ = *first_in++;
				}
			}

			template<typename Iterator, typename U>
			constexpr void fill_values( Iterator first, size_t count, U const value ) noexcept {
				for( size_t n=0; n<count; ++n ) {
					*first++ = value;
				}
			}

		  public:
			constexpr sha2_ctx( ) noexcept
			    : m_tot_len{0}, m_len{0}, m_block{}, m_h{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
			                                              0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19} {}
		private:
			// len cannot be longer than block_size
			constexpr void update_impl( byte_t const *message, size_t const len ) noexcept {
				size_t const tmp_len = block_size - m_len;
				size_t rem_len = len < tmp_len ? len : tmp_len;

				// fill block buffer with message data
				m_block.push_back( message, rem_len );
				//copy_values( message, rem_len, &m_block[m_len] );
				if( m_len + len < block_size ) {
					m_len += len;
					return;
				}

				size_t const new_len = len - rem_len;
				size_t const block_nb = new_len / block_size;
				byte_t const * shifted_message = message + rem_len;

				transform( m_block.data( ), 1u );
				transform( shifted_message, block_nb );
				rem_len = new_len % block_size;

				m_block.clear( );
				m_block.push_back( &shifted_message[block_nb * 64u], rem_len );
				//copy_values( &shifted_message[block_nb * 64u], rem_len, m_block.data( ) );
				m_len = rem_len;
				m_tot_len += ( block_nb + 1u ) * 64u;
			}
		
		public:
			template<typename CharT>
			constexpr void update( CharT const *message, size_t len ) noexcept {
				auto msg = daw::make_array_view( static_cast<byte_t const *>( static_cast<void const *>( message ) ),
				                                 len * sizeof( CharT ) );
				while( msg.size( ) > block_size ) {
					update_impl( msg.data( ), block_size );
					msg.remove_prefix( block_size );
				}
				update_impl( msg.data( ), msg.size( ) );
			}

			constexpr sha256_digest_t create_digest( ) noexcept {
				return sha256_digest_t{ };
			}

		  private:
			constexpr void final_padding( ) noexcept {


			}
		  public:
			constexpr void final( sha256_digest_t & digest ) noexcept {
				size_t const block_nb = 1 + (( ( block_size - 9u ) < ( m_len % block_size ) ) ? 1 : 0);
				auto const len_b = static_cast<word_t>(( m_tot_len + m_len ) * 8u);
				size_t const pm_len = block_nb * 64u;

				fill_values( &m_block[m_len], pm_len - m_len, static_cast<byte_t>(0) );

				m_block[m_len] = 0x80u;

				impl::SHA2_UNPACK32( len_b, &m_block[pm_len - 4u] );

				transform( m_block.data( ), block_nb );
				for( size_t i = 0; i < 8; i++ ) {
					impl::SHA2_UNPACK32( m_h[i], &digest[i * 4u] );
				}
			}

			constexpr sha256_digest_t final( ) noexcept {
				sha256_digest_t digest{};
				final( digest );
				return digest;
			}
		};

		using sha256_ctx = sha2_ctx<256, unsigned char>;

		template<typename T = char>
		constexpr auto sha256_bin( daw::array_view<T> view ) noexcept {
			sha2_ctx<256, T> ctx{};
			while( view.size( ) > ctx.block_size ) {
				ctx.update( view.data( ), ctx.block_size );
				view.remove_prefix( ctx.block_size );
			}
			ctx.update( view.data( ), static_cast<uint32_t>( view.size( ) ) );
			return ctx.final( );
		}

		template<typename Container>
		constexpr auto sha256_bin( Container const &container ) noexcept {
			return sha256_bin(
			    daw::make_array_view( reinterpret_cast<sha256_ctx::byte_t const *>( &( *std::cbegin( container ) ) ),
			                          reinterpret_cast<sha256_ctx::byte_t const *>( &( *std::cend( container ) ) ) ) );
		}

		template<typename Iterator>
		constexpr auto sha256_bin( Iterator const first, Iterator const last ) noexcept {
			return sha256_bin( daw::make_array_view( reinterpret_cast<sha256_ctx::byte_t const *>( &( *first ) ),
			                                         reinterpret_cast<sha256_ctx::byte_t const *>( &( *last ) ) ) );
		}

		template<typename String>
		std::string sha256( String const &str ) noexcept {
			return sha256_bin( std::cbegin( str ), std::cend( str ) ).to_hex_string( );
		}

		template<typename CharT, size_t N>
		std::string sha256( CharT const ( &s )[N] ) noexcept {
			return sha256_bin( s, s + N - 1 ).to_hex_string( );
		}

	} // namespace crypto
} // namespace daw

