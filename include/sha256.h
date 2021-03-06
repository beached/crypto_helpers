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

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>

#include <daw/daw_bounded_vector.h>
#include <daw/daw_random.h>
#include <daw/daw_span.h>
#include <daw/daw_string_view.h>

namespace daw {
	namespace crypto {
		namespace impl {
			template<size_t bits, typename word_t>
			constexpr auto SHA2_SHFR( word_t const x ) noexcept {
				static_assert( bits <= sizeof( word_t ) * 8,
				               "Cannot shift more than word size bits" );
				return x >> bits;
			}

			template<size_t bits, typename word_t>
			constexpr auto SHA2_ROTR( word_t const x ) noexcept {
				static_assert( bits <= sizeof( word_t ) * 8,
				               "Cannot shift more than word size bits" );
				return ( x >> bits ) | ( x << ( ( sizeof( word_t ) * 8 ) - bits ) );
			}

			template<typename word_t>
			constexpr auto SHA256_CH( word_t const x, word_t const y,
			                          word_t const z ) noexcept {
				return ( x & y ) ^ ( ~x & z );
			}

			template<typename word_t>
			constexpr auto SHA256_MAJ( word_t const x, word_t const y,
			                           word_t const z ) noexcept {
				return ( x & y ) ^ ( x & z ) ^ ( y & z );
			}

			template<typename word_t>
			constexpr auto SHA256_EP0( word_t const x ) noexcept {
				return SHA2_ROTR<2u>( x ) ^ SHA2_ROTR<13u>( x ) ^ SHA2_ROTR<22u>( x );
			}

			template<typename word_t>
			constexpr auto SHA256_EP1( word_t const x ) noexcept {
				return SHA2_ROTR<6u>( x ) ^ SHA2_ROTR<11u>( x ) ^ SHA2_ROTR<25u>( x );
			}

			template<typename word_t>
			constexpr auto SHA256_SIG0( word_t const x ) noexcept {
				return SHA2_ROTR<7u>( x ) ^ SHA2_ROTR<18u>( x ) ^ SHA2_SHFR<3u>( x );
			}

			template<typename word_t>
			constexpr auto SHA256_SIG1( word_t const x ) noexcept {
				return SHA2_ROTR<17u>( x ) ^ SHA2_ROTR<19u>( x ) ^ SHA2_SHFR<10u>( x );
			}

#ifdef LITTLE_ENDIAN
			constexpr uint32_t to_uint32_be( uint8_t const *ptr ) noexcept {
				return static_cast<uint32_t>( static_cast<uint8_t>( ptr[0] ) << 24u ) |
				       static_cast<uint32_t>( static_cast<uint8_t>( ptr[1] ) << 16u ) |
				       static_cast<uint32_t>( static_cast<uint8_t>( ptr[2] ) << 8u ) |
				       static_cast<uint32_t>( static_cast<uint8_t>( ptr[3] ) );
			}

			template<typename CharT>
			constexpr void to_uint64_be( CharT *ptr, uint64_t const value ) noexcept {
				ptr[0] =
				  static_cast<CharT>( ( value & 0xFF'00'00'00'00'00'00'00 ) >> 56u );
				ptr[1] =
				  static_cast<CharT>( ( value & 0x00'FF'00'00'00'00'00'00 ) >> 48u );
				ptr[2] =
				  static_cast<CharT>( ( value & 0x00'00'FF'00'00'00'00'00 ) >> 40u );
				ptr[3] =
				  static_cast<CharT>( ( value & 0x00'00'00'FF'00'00'00'00 ) >> 32u );
				ptr[4] =
				  static_cast<CharT>( ( value & 0x00'00'00'00'FF'00'00'00 ) >> 24u );
				ptr[5] =
				  static_cast<CharT>( ( value & 0x00'00'00'00'00'FF'00'00 ) >> 16u );
				ptr[6] =
				  static_cast<CharT>( ( value & 0x00'00'00'00'00'00'FF'00 ) >> 8u );
				ptr[7] = static_cast<CharT>( ( value & 0x00'00'00'00'00'00'00'FF ) );
			}
#else

			template<typename CharT>
			constexpr uint32_t to_uint32_be( CharT const *ptr ) noexcept {
				return static_cast<uint32_t>( static_cast<uint8_t>( ptr[0] ) ) |
				       static_cast<uint32_t>( static_cast<uint8_t>( ptr[1] ) << 8u ) |
				       static_cast<uint32_t>( static_cast<uint8_t>( ptr[2] ) << 16u ) |
				       static_cast<uint32_t>( static_cast<uint8_t>( ptr[3] ) << 24u );
			}

			template<typename CharT>
			constexpr void to_uint64_be( CharT *ptr, uint64_t const value ) noexcept {
				ptr[0] = static_cast<CharT>( value & 0x00'00'00'00'00'00'00'FF );
				ptr[1] =
				  static_cast<CharT>( ( value & 0x00'00'00'00'00'00'FF'00 ) >> 8u );
				ptr[2] =
				  static_cast<CharT>( ( value & 0x00'00'00'00'00'FF'00'00 ) >> 16u );
				ptr[3] =
				  static_cast<CharT>( ( value & 0x00'00'00'00'FF'00'00'00 ) >> 24u );
				ptr[4] =
				  static_cast<CharT>( ( value & 0x00'00'00'FF'00'00'00'00 ) >> 32u );
				ptr[5] =
				  static_cast<CharT>( ( value & 0x00'00'FF'00'00'00'00'00 ) >> 40u );
				ptr[6] =
				  static_cast<CharT>( ( value & 0x00'FF'00'00'00'00'00'00 ) >> 48u );
				ptr[7] =
				  static_cast<CharT>( ( value & 0xFF'00'00'00'00'00'00'00 ) >> 56u );
			}
#endif

			template<typename T, size_t DigestSize>
			struct digest_t {
				using value_t = T;
				using reference = value_t &;
				using const_reference = value_t const &;
				static size_t const digest_size = DigestSize;
				alignas( 64 ) std::array<value_t, digest_size> data;

				std::string to_hex_string( ) const {
					std::stringstream ss;
					for( size_t n = 0; n < data.size( ); ++n ) {
						ss << std::setfill( '0' ) << std::setw( sizeof( data[n] ) * 2 )
						   << std::hex << data[n];
					}
					return ss.str( );
				}

				constexpr size_t size( ) const noexcept {
					return data.size( );
				}

				constexpr reference operator[]( size_t pos ) noexcept {
					return data[pos];
				}

				constexpr const_reference operator[]( size_t pos ) const noexcept {
					return data[pos];
				}

				constexpr bool operator==( digest_t const &rhs ) noexcept {
					return std::equal( data.cbegin( ), data.cend( ), rhs.data.cbegin( ),
					                   rhs.data.cend( ) );
				}

				constexpr bool operator!=( digest_t const &rhs ) noexcept {
					bool is_not_equal = true;
					for( size_t n = 0; n < digest_size; ++n ) {
						is_not_equal &= data[n] != rhs.data[n];
					}
					return is_not_equal;
				}

				constexpr bool operator<( digest_t const &rhs ) noexcept {
					bool is_less = true;
					for( size_t n = 0; n < digest_size; ++n ) {
						is_less &= data[n] < rhs.data[n];
					}
					return is_less;
				}

				constexpr bool operator>( digest_t const &rhs ) noexcept {
					bool is_greater = true;
					for( size_t n = 0; n < digest_size; ++n ) {
						is_greater &= data[n] > rhs.data[n];
					}
					return is_greater;
				}

				constexpr bool operator<=( digest_t const &rhs ) noexcept {
					bool is_less_equal = true;
					for( size_t n = 0; n < digest_size; ++n ) {
						is_less_equal &= data[n] <= rhs.data[n];
					}
					return is_less_equal;
				}

				constexpr bool operator>=( digest_t const &rhs ) noexcept {
					bool is_greater_equal = true;
					for( size_t n = 0; n < digest_size; ++n ) {
						is_greater_equal &= data[n] >= rhs.data[n];
					}
					return is_greater_equal;
				}
			};

			template<typename word_t>
			alignas( 64 ) constexpr std::array<word_t const, 64> const sha256_k{
			  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
			  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
			  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
			  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
			  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
			  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
			  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
			  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
			  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
		} // namespace impl

		using sha256_digest_t = impl::digest_t<uint32_t, 8>;

		namespace impl {
			template<typename word_t>
			constexpr sha256_digest_t const sha256_init_state_values{
			  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
			  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
			constexpr char to_nibble( uint8_t c ) noexcept {
				if( c < 10 ) {
					return static_cast<char>( c ) + '0';
				}
				return ( static_cast<char>( c ) - 10 ) + 'a';
			}
		} // namespace impl

		template<size_t digest_size, typename>
		struct sha2_ctx;

		template<typename T>
		struct sha2_ctx<256, T> {
			using word_t = uint32_t;
			using byte_t = unsigned char;
			static constexpr size_t const block_size_bytes = 64; // 512 bits
			static constexpr size_t const digest_size =
			  8; // 256/(32bit wordsize) bits

		private:
			uint64_t m_message_size;
			daw::bounded_vector_t<byte_t, block_size_bytes> m_message_block;
			sha256_digest_t m_state;

		public:
			constexpr sha2_ctx( ) noexcept
			  : m_message_size{0}
			  , m_message_block{}
			  , m_state{impl::sha256_init_state_values<word_t>} {}

		private:
			constexpr void transform( ) noexcept {
				/*
				 * Initialize array of round constants:
				 * (first 32 bits of the fractional parts of the cube roots of the first
				 * 64 primes 2..311):
				 */
				alignas( 64 ) std::array<word_t, 64> w{0};
				// Copy message to first 16 words of w array
				{
					auto message_view =
					  daw::span( m_message_block.data( ), m_message_block.size( ) );
					for( size_t i = 0; i < 16; ++i ) {
						w[i] = impl::to_uint32_be( message_view.data( ) );
						message_view.remove_prefix( 4 );
					}
				}

				for( size_t i = 16; i < 64; ++i ) {
					word_t const s0 = impl::SHA256_SIG0( w[i - 15] );
					word_t const s1 = impl::SHA256_SIG1( w[i - 2] );
					w[i] = w[i - 16] + s0 + w[i - 7] + s1;
				}

				alignas( 64 ) std::array<word_t, 10> tmp_state{
				  m_state[0], m_state[1], m_state[2], m_state[3], m_state[4],
				  m_state[5], m_state[6], m_state[7], 0,          0};

				for( size_t i = 0; i < 64; ++i ) {
					tmp_state[8] =
					  tmp_state[7] + impl::SHA256_EP1( tmp_state[4] ) +
					  impl::SHA256_CH( tmp_state[4], tmp_state[5], tmp_state[6] ) +
					  impl::sha256_k<word_t>[i] + w[i];
					tmp_state[9] =
					  impl::SHA256_EP0( tmp_state[0] ) +
					  impl::SHA256_MAJ( tmp_state[0], tmp_state[1], tmp_state[2] );
					tmp_state[7] = tmp_state[6];
					tmp_state[6] = tmp_state[5];
					tmp_state[5] = tmp_state[4];
					tmp_state[4] = tmp_state[3] + tmp_state[8];
					tmp_state[3] = tmp_state[2];
					tmp_state[2] = tmp_state[1];
					tmp_state[1] = tmp_state[0];
					tmp_state[0] = tmp_state[8] + tmp_state[9];
				}

				m_state[0] += tmp_state[0];
				m_state[1] += tmp_state[1];
				m_state[2] += tmp_state[2];
				m_state[3] += tmp_state[3];
				m_state[4] += tmp_state[4];
				m_state[5] += tmp_state[5];
				m_state[6] += tmp_state[6];
				m_state[7] += tmp_state[7];

				m_message_size += m_message_block.capacity( ) * 8;
				m_message_block.clear( );
			}

			template<typename ArrayView>
			constexpr void update_impl( ArrayView view ) noexcept {
				size_t push_size = 1;
				while( view.size( ) > m_message_block.capacity( ) ) {
					push_size = std::min( view.size( ), m_message_block.available( ) );
					m_message_block.push_back( view.data( ), push_size );
					transform( );
					view.remove_prefix( push_size );
				}
				if( !view.empty( ) ) {
					push_size = std::min( view.size( ), m_message_block.available( ) );
					m_message_block.push_back( view.data( ), push_size );
					if( m_message_block.full( ) ) {
						transform( );
					}
					view.remove_prefix( push_size );
				}
			}

			template<typename Iterator>
			constexpr void update_impl( Iterator first, Iterator last ) noexcept {
				while( first != last ) {
					m_message_block.push_back( *first++ );
					if( m_message_block.full( ) ) {
						transform( );
					}
				}
			}

			constexpr void final_padding( ) noexcept {
				// Can never be full as we would have processed it in update step
				m_message_block.push_back( 0b1000'0000 );
				if( m_message_block.size( ) > 56 ) {
					while( !m_message_block.full( ) ) {
						m_message_block.push_back( 0 );
					}
					transform( );
				}
				while( m_message_block.size( ) < 56 ) {
					m_message_block.push_back( 0 );
				}
			}

		public:
			constexpr void update( T const *message, size_t len ) noexcept {
				auto view = daw::span( message, len );
				update_impl( view );
			}

			template<typename Traits>
			constexpr void update( daw::basic_string_view<T, Traits> view ) noexcept {
				update_impl( std::move( view ) );
			}

			template<typename U, typename = std::enable_if_t<sizeof( U ) == 1>>
			constexpr void update( daw::span<U const> view ) noexcept {
				update_impl( std::move( view ) );
			}

			template<
			  typename Iterator,
			  typename = std::enable_if_t<
			    sizeof( typename std::iterator_traits<Iterator>::value_type ) == 1>>
			constexpr void update( Iterator first, Iterator last ) noexcept {
				update_impl( first, last );
			}

			static constexpr sha256_digest_t create_digest( ) noexcept {
				return sha256_digest_t{};
			}

			constexpr void final( sha256_digest_t &digest ) noexcept {
				auto const message_size =
				  m_message_size + ( m_message_block.size( ) * 8 );
				final_padding( );

				auto size_begin = m_message_block.end( );
				while( !m_message_block.full( ) ) {
					m_message_block.push_back( 0 );
				}
				impl::to_uint64_be( size_begin, message_size );

				transform( );

				for( size_t i = 0; i < digest.size( ); ++i ) {
					digest[i] = m_state[i];
				}
			}

			constexpr sha256_digest_t final( ) noexcept {
				sha256_digest_t digest{};
				final( digest );
				return digest;
			}
		}; // sha256_ctx

		using sha256_ctx = sha2_ctx<256, unsigned char>;

		template<typename CharT, typename Traits,
		         typename = std::enable_if_t<sizeof( CharT ) == 1>>
		constexpr sha256_digest_t
		sha256_bin( daw::basic_string_view<CharT, Traits> sv ) noexcept {
			sha2_ctx<256, CharT> ctx{};
			ctx.update( sv.data( ), sv.size( ) );
			return ctx.final( );
		}

		template<typename CharT, typename = std::enable_if_t<sizeof( CharT ) == 1>>
		constexpr sha256_digest_t sha256_bin( CharT const *str,
		                                      size_t len ) noexcept {
			sha2_ctx<256, CharT> ctx{};
			ctx.update( str, len );
			return ctx.final( );
		}

		template<typename CharT, size_t N,
		         typename = std::enable_if_t<sizeof( CharT ) == 1>>
		constexpr sha256_digest_t sha256_bin( CharT const ( &str )[N] ) noexcept {
			sha2_ctx<256, CharT> ctx{};
			ctx.update( str, N - 1 );
			return ctx.final( );
		}

		class sha256_hash_string {
			char m_data[65];

		public:
			explicit constexpr sha256_hash_string(
			  sha256_digest_t const &digest ) noexcept
			  : m_data{0} {
				for( size_t n = 0; n < digest.size( ); ++n ) {
					auto w = digest[n];
					for( size_t m = 8; m > 0; --m ) {
						m_data[( 8 * n ) + m - 1] =
						  impl::to_nibble( static_cast<uint8_t>( w & 0x0000000F ) );
						w >>= 4;
					}
				}
			}

			constexpr char const *c_str( ) const noexcept {
				return m_data;
			}

			constexpr operator char const *( ) const noexcept {
				return m_data;
			}
		};

		template<typename CharT, typename Traits,
		         typename = std::enable_if_t<sizeof( CharT ) == 1>>
		constexpr sha256_hash_string
		sha256( daw::basic_string_view<char, Traits> sv ) noexcept {
			return daw::crypto::sha256_hash_string{daw::crypto::sha256_bin( sv )};
		}

		template<typename CharT, typename = std::enable_if_t<sizeof( CharT ) == 1>>
		constexpr sha256_hash_string sha256( CharT const *str,
		                                     size_t len ) noexcept {
			return daw::crypto::sha256_hash_string{
			  daw::crypto::sha256_bin( str, len )};
		}

		template<typename CharT, size_t N,
		         typename = std::enable_if_t<sizeof( CharT ) == 1>>
		constexpr sha256_hash_string sha256( CharT const ( &str )[N] ) noexcept {
			return daw::crypto::sha256_hash_string{daw::crypto::sha256_bin( str )};
		}

		template<typename... Args>
		inline std::string sha256str( Args &&... args ) noexcept {
			return std::string{sha256( std::forward<Args>( args )... )};
		}
	} // namespace crypto

	namespace crypto_literals {
		constexpr daw::crypto::sha256_digest_t
		operator"" _sha256_digest( char const *str, size_t len ) noexcept {
			return daw::crypto::sha256_bin( str, len );
		}

		constexpr daw::crypto::sha256_hash_string
		operator"" _sha256( char const *str, size_t len ) noexcept {
			return daw::crypto::sha256_hash_string{
			  daw::crypto::sha256_bin( str, len )};
		}

		inline std::string operator"" _sha256str( char const *str, size_t len ) {
			return daw::crypto::sha256_bin( str, len ).to_hex_string( );
		}
	} // namespace crypto_literals
} // namespace daw

