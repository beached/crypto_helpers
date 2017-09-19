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

#include <daw/daw_string_view.h>

namespace daw {
	namespace crypto {
		namespace impl {
			template<typename T, typename U>
			constexpr auto SHA2_SHFR( T const x, U const n ) noexcept {
				return x >> n;
			}

			template<typename T, typename U>
			constexpr auto SHA2_ROTR( T const x, U const n ) noexcept {
				return ( x >> n ) | ( x << ( ( sizeof( x ) << 3 ) - n ) );
			}

			template<typename T, typename U>
			constexpr auto SHA2_ROTL( T const x, U const n ) noexcept {
				return ( x << n ) | ( x >> ( ( sizeof( x ) << 3 ) - n ) );
			}

			template<typename T, typename U, typename V>
			constexpr auto SHA2_CH( T const x, U const y, V const z ) noexcept {
				return ( x & y ) ^ ( ~x & z );
			}

			template<typename T, typename U, typename V>
			constexpr auto SHA2_MAJ( T const x, U const y, V const z ) noexcept {
				return ( x & y ) ^ ( x & z ) ^ ( y & z );
			}

			template<typename T>
			constexpr auto SHA256_F1( T const x ) noexcept {
				return SHA2_ROTR( x, 2 ) ^ SHA2_ROTR( x, 13 ) ^ SHA2_ROTR( x, 22 );
			}

			template<typename T>
			constexpr auto SHA256_F2( T const x ) noexcept {
				return SHA2_ROTR( x, 6 ) ^ SHA2_ROTR( x, 11 ) ^ SHA2_ROTR( x, 25 );
			}

			template<typename T>
			constexpr auto SHA256_F3( T const x ) noexcept {
				return SHA2_ROTR( x, 7 ) ^ SHA2_ROTR( x, 18 ) ^ SHA2_SHFR( x, 3 );
			}

			template<typename T>
			constexpr auto SHA256_F4( T const x ) noexcept {
				return SHA2_ROTR( x, 17 ) ^ SHA2_ROTR( x, 19 ) ^ SHA2_SHFR( x, 10 );
			}

			template<typename T, typename Ptr>
			constexpr void SHA2_UNPACK32( T x, Ptr str ) noexcept {
				*( ( str ) + 3 ) = static_cast<char>( ( x ) );
				*( ( str ) + 2 ) = static_cast<char>( ( x ) >> 8 );
				*( ( str ) + 1 ) = static_cast<char>( ( x ) >> 16 );
				*( ( str ) + 0 ) = static_cast<char>( ( x ) >> 24 );
			}

			template<typename Ptr, typename T>
			constexpr void SHA2_PACK32( Ptr str, T x ) noexcept {
				*( x ) = static_cast<uint32_t>( *( ( str ) + 3 ) ) |
				         ( static_cast<uint32_t>( *( ( str ) + 2 ) ) << 8 ) |
				         ( static_cast<uint32_t>( *( ( str ) + 1 ) ) << 16 ) |
				         ( static_cast<uint32_t>( *( ( str ) + 0 ) ) << 24 );
			}

			std::array<uint32_t, 64> const &sha256_k( ) noexcept;
		} // namespace impl

		template<typename CharT>
		struct sha256_ctx {
			static_assert( sizeof( CharT ) == 1, "Only byte sized data allowed" );
			static constexpr size_t const SHA224_256_BLOCK_SIZE = ( 512 / 8 );
			static constexpr size_t const DIGEST_SIZE = ( 256 / 8 );

		  private:
			size_t m_tot_len;
			size_t m_len;
			std::array<CharT, 2 * SHA224_256_BLOCK_SIZE> m_block;
			std::array<uint32_t, 8> m_h;

			constexpr void transform( CharT const *message, size_t const block_nb ) noexcept {
				std::array<uint32_t, 64> const sha256_k = {
				    {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
				     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
				     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
				     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
				     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
				     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
				     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
				     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2}};

				std::array<uint32_t, 64> w = {0};
				std::array<uint32_t, 8> wv = {0};
				uint32_t t1 = 0;
				uint32_t t2 = 0;
				CharT const *sub_block = nullptr;
				size_t j = 0;
				for( size_t i = 0; i < block_nb; i++ ) {
					sub_block = message + ( i << 6 );
					for( j = 0; j < 16; j++ ) {
						impl::SHA2_PACK32( &sub_block[j << 2], &w[j] );
					}
					for( j = 16; j < 64; j++ ) {
						w[j] = impl::SHA256_F4( w[j - 2] ) + w[j - 7] + impl::SHA256_F3( w[j - 15] ) + w[j - 16];
					}
					for( j = 0; j < 8; j++ ) {
						wv[j] = m_h[j];
					}
					for( j = 0; j < 64; j++ ) {
						t1 = wv[7] + impl::SHA256_F2( wv[4] ) + impl::SHA2_CH( wv[4], wv[5], wv[6] ) + sha256_k[j] + w[j];
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

			template<typename T, size_t N>
			constexpr void transform( std::array<T, N> const &message, size_t block_nb ) noexcept {
				return transform( message.data( ), block_nb );
			}

		  public:
			constexpr void init( ) noexcept {
				m_h[0] = 0x6a09e667;
				m_h[1] = 0xbb67ae85;
				m_h[2] = 0x3c6ef372;
				m_h[3] = 0xa54ff53a;
				m_h[4] = 0x510e527f;
				m_h[5] = 0x9b05688c;
				m_h[6] = 0x1f83d9ab;
				m_h[7] = 0x5be0cd19;
				m_len = 0;
				m_tot_len = 0;
			}

			constexpr void update( CharT const *message, size_t const len ) noexcept {
				size_t block_nb = 0;
				size_t new_len = 0;
				size_t rem_len = 0;
				size_t tmp_len = 0;
				CharT const *shifted_message = nullptr;
				tmp_len = SHA224_256_BLOCK_SIZE - m_len;
				rem_len = len < tmp_len ? len : tmp_len;
				std::copy( message, std::next( message, rem_len ), std::next( m_block.data( ), m_len ) );
				if( m_len + len < SHA224_256_BLOCK_SIZE ) {
					m_len += len;
					return;
				}
				new_len = len - rem_len;
				block_nb = new_len / SHA224_256_BLOCK_SIZE;
				shifted_message = message + rem_len;
				transform( m_block.data( ), 1 );
				transform( shifted_message, block_nb );
				rem_len = new_len % SHA224_256_BLOCK_SIZE;
				{
					auto const first = std::next( shifted_message, block_nb << 6 );
					std::copy( first, std::next( first, rem_len ), m_block.data( ) );
				}
				m_len = rem_len;
				m_tot_len += ( block_nb + 1 ) << 6;
			}

			constexpr void final( CharT *digest ) noexcept {
				unsigned int block_nb = 0;
				unsigned int pm_len = 0;
				unsigned int len_b = 0;
				int i = 0;
				block_nb = ( 1 + ( ( SHA224_256_BLOCK_SIZE - 9 ) < ( m_len % SHA224_256_BLOCK_SIZE ) ) );
				len_b = ( m_tot_len + m_len ) << 3;
				pm_len = block_nb << 6;
				//memset( m_block.data( ) + m_len, 0, pm_len - m_len );
				{
					auto const first = std::next( m_block.data( ), m_len );
					std::fill( first, std::next( first, pm_len - m_len ), 0 );
				}
				m_block[m_len] = static_cast<CharT>( 0x80 );
				impl::SHA2_UNPACK32( len_b, m_block.data( ) + pm_len - 4 );
				transform( m_block.data( ), block_nb );
				for( i = 0; i < 8; i++ ) {
					impl::SHA2_UNPACK32( m_h[i], &digest[i << 2] );
				}
			}
		};

		namespace impl {
			constexpr uint8_t to_nibble( uint8_t c ) noexcept {
				c &= 0x0F;
				if( c < 10 ) {
					return '0' + c;
				}
				return 'a' + ( c - 10 );
			}

			constexpr uint16_t to_hex( uint8_t c ) noexcept {
				uint16_t result = to_nibble( c >> 4 ) << 8;
				result |= to_nibble( c );
				return result;
			}
		} // namespace impl

		template<typename CharT, typename Traits, typename InternalSizeType>
		std::string sha256( daw::basic_string_view<CharT, Traits, InternalSizeType> input ) noexcept {
			static_assert( sizeof( CharT ) == 1, "Only byte sized data allowed" );
			std::array<CharT, sha256_ctx<CharT>::DIGEST_SIZE> digest;
			std::fill( digest.begin( ), digest.end( ), 0 );

			sha256_ctx<uint8_t> ctx{};
			ctx.init( );
			ctx.update( reinterpret_cast<uint8_t const *>( input.data( ) ), input.size( ) );
			ctx.final( reinterpret_cast<uint8_t *>( digest.data( ) ) );

			std::stringstream ss;
			for( auto const c : digest ) {
				auto as_hex = impl::to_hex( c );
				ss << static_cast<char>( ( as_hex & 0xFF00 ) >> 8 ) << static_cast<char>( as_hex & 0x00FF );
			}
			return ss.str( );
		}
		template<typename CharT, typename Traits>
		std::string sha256( std::basic_string<CharT, Traits> const &input ) noexcept {
			daw::string_view sv{ input.data( ), input.size( ) };
			return sha256( sv );
		}

		template<typename Str>
		std::string sha256( Str const &str ) {
			std::string str_str = str;
			return sha256( str_str );
		}
	} // namespace crypto
} // namespace daw

