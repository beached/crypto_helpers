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

#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>

#include <daw/daw_array_view.h>
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

		template<size_t digest_size, typename>
		struct sha2_ctx;

		template<typename T>
		struct sha2_ctx<256, T> {
			using word_t = uint32_t;
			static constexpr size_t const block_size = (512/8);	// 512 bits
			static constexpr size_t const digest_size = ( 256 / 8 ); // 256 bits
			struct digest_t {
				std::array<uint8_t, digest_size> data;

				constexpr digest_t( ) noexcept: data{{0}} {}

				std::string to_hex_string( ) const {
					std::stringstream ss;
					for( auto const c : data ) {
						auto as_hex = impl::to_hex( c );
						ss << static_cast<char>( ( as_hex & 0xFF00 ) >> 8 ) << static_cast<char>( as_hex & 0x00FF );
					}
					return ss.str( );
				}
			};
		  private:
			word_t m_tot_len;
			word_t m_len;
			std::array<uint8_t, 2 * block_size> m_block;
			std::array<word_t, 8> m_h;

			constexpr void transform( uint8_t const *message, size_t const block_nb ) noexcept {
				std::array<word_t, 64> const sha256_k = {
				    {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
				     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
				     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
				     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
				     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
				     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
				     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
				     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2}};

				std::array<word_t, 64> w = {0};
				std::array<word_t, 8> wv = {0};
				word_t t1 = 0;
				word_t t2 = 0;
				uint8_t const *sub_block = nullptr;
				size_t j = 0;
				for( size_t i = 0; i < block_nb; i++ ) {
					sub_block = message + ( i << 6 );
					for( j = 0; j < 16; j++ ) {
						impl::SHA2_PACK32( &sub_block[j << 2], w[j] );
					}
					for( j = 16; j < 64; j++ ) {
						w[j] = impl::SHA256_F4( w[j - 2] ) + w[j - 7] + impl::SHA256_F3( w[j - 15] ) + w[j - 16];
					}
					for( j = 0; j < 8; j++ ) {
						wv[j] = m_h[j];
					}
					for( j = 0; j < 64; j++ ) {
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
					for( j = 0; j < 8; j++ ) {
						m_h[j] += wv[j];
					}
				}
			}

			template<typename U, size_t N>
			constexpr void transform( std::array<U, N> const &message, size_t const block_nb ) noexcept {
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
			    : m_tot_len{0}, m_len{0}, m_block{0}, m_h{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
			                                              0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19} {}

			constexpr void update_impl( uint8_t const *message, uint32_t const len ) noexcept {
				assert( len <= block_size );
				word_t block_nb = 0;
				word_t new_len = 0;
				word_t rem_len = 0;
				word_t tmp_len = 0;
				uint8_t const *shifted_message = nullptr;
				tmp_len = block_size - m_len;
				rem_len = len < tmp_len ? len : tmp_len;
				copy_values( message, rem_len, &m_block[m_len] );
				if( m_len + len < block_size ) {
					m_len += len;
					return;
				}
				new_len = len - rem_len;
				block_nb = new_len / block_size;
				shifted_message = message + rem_len;
				transform( m_block.data( ), 1u );
				transform( shifted_message, block_nb );
				rem_len = new_len % block_size;
				copy_values( &shifted_message[block_nb << 6u], rem_len, m_block.data( ) );
				m_len = rem_len;
				m_tot_len += ( block_nb + 1u ) << 6u;
			}

			void update( T const *message, size_t len ) noexcept {
				auto ptr = static_cast<uint8_t const *>( static_cast<void const *>( message ) );
				len *= sizeof( T );
				while( len > 0 ) {
					auto const sz = static_cast<uint32_t>( std::min( block_size, len ) );
					update_impl( ptr, sz );
					if( sz <= len ) {
						ptr += sz;
						len -= sz;
					}
				}
			}

			constexpr digest_t create_digest( ) noexcept {
				return digest_t{ };
			}

			constexpr void final( digest_t & digest ) noexcept {
				word_t const block_nb = ( 1u + ( ( block_size - 9u ) < ( m_len % block_size ) ) );
				auto const len_b = static_cast<word_t>(( m_tot_len + m_len ) << 3u);
				word_t const pm_len = block_nb << 6u;
				fill_values( &m_block[m_len], pm_len - m_len, static_cast<uint8_t>(0) );
				m_block[m_len] = 0x80u;
				impl::SHA2_UNPACK32( len_b, m_block.data( ) + pm_len - 4u );
				transform( m_block.data( ), block_nb );
				for( size_t i = 0; i < 8; i++ ) {
					impl::SHA2_UNPACK32( m_h[i], &digest.data[i << 2u] );
				}
			}

			constexpr digest_t final( ) noexcept {
				digest_t digest{};
				final( digest );
				return digest;
			}
		};

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
			    daw::make_array_view( reinterpret_cast<uint8_t const *>( &( *std::cbegin( container ) ) ),
			                          reinterpret_cast<uint8_t const *>( &( *std::cend( container ) ) ) ) );
		}

		template<typename Iterator>
		constexpr auto sha256_bin( Iterator const first, Iterator const last ) noexcept {
			return sha256_bin( daw::make_array_view( reinterpret_cast<uint8_t const *>( &( *first ) ),
			                                         reinterpret_cast<uint8_t const *>( &( *last ) ) ) );
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

