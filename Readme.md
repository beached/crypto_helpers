### Crypto Helpers

## SHA256 - in constexpr

# literals
""_sha256 Creates a sha256_hash_string(struct that is implicitly convertable to a c_str) at compile time
""_sha256_digest Creates a SHA256 digest at compile time 
""_sha256str Creates a std::string of the SHA256 hash

# Literal Examples
``` C++
using daw::crypto_literals;
auto hash = "Hello Word"_sha256
std::cout << hash << '\n';
```
Would output
```
a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
```

# Function calls
The sha256_bin( some string like thing ) genrate a sha256 digest which contains the binary hash
``` C++
template<typename CharT, typename Traits, typename IntSizeType, typename = std::enable_if_t<sizeof( CharT ) == 1>>
constexpr sha256_digest_t sha256_bin( daw::basic_string_view<CharT, Traits, IntSizeType> sv ) noexcept;

template<typename CharT, typename = std::enable_if_t<sizeof( CharT ) == 1>>
constexpr sha256_digest_t sha256_bin( CharT const *str, size_t len ) noexcept;

template<typename CharT, size_t N, typename = std::enable_if_t<sizeof( CharT ) == 1>>
constexpr sha256_digest_t sha256_bin( CharT const ( &str )[N] ) noexcept;
```

The sha256( some string like thing ) creates a sha256_hash_string which is implicitly converable to a c_str.  sha256str will create std::string but lacks constexpr

``` C++
template<typename CharT, typename Traits, typename IntSizeType, typename = std::enable_if_t<sizeof( CharT ) == 1>>
constexpr sha256_hash_string sha256( daw::basic_string_view<char, Traits, IntSizeType> sv ) noexcept;

template<typename CharT, typename = std::enable_if_t<sizeof( CharT ) == 1>>
constexpr sha256_hash_string sha256( CharT const *str, size_t len ) noexcept;

template<typename CharT, size_t N, typename = std::enable_if_t<sizeof( CharT ) == 1>>
constexpr sha256_hash_string sha256( CharT const ( &str )[N] ) noexcept;

template<typename...Args>
inline std::string sha256str( Args&&... args ) noexcept;
```

