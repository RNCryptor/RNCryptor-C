## Table Of Contents
- [v1.07](#v107)
- [v1.06](#v106)
- [v1.05](#v105)
- [v1.04](#v104)
- [v1.03](#v103)
- [v1.02](#v102)
- [v1.01](#v101)

# v1.07
- Fix 8x over-allocation in `cipher_text malloc (sizeof unsigned char* ->
unsigned char)`, remove stray double semicolon. No security issue.

- ruby `MiniTest` is now `Minitest`. Add `i_suck_and_my_tests_are_order_dependent!`
in the class to force test orders. Tests use generated files from one test to
another so call order is important.

- Add OpenSSL 3.x support via `EVP_MAC` API, fix HMAC/cipher context 
memory leaks. Clean key material on exit.

- Code cleanup to remove compiler warnings.

- Move docs from AsciiDoc to Markdown format.

(Mar-07-2026)

# v1.06
- Support OpenSSL 1.1 (tested with OpenSSL 1.1.1d) and LibreSSL (tested
  with LibreSSL 3.0.2). Fixes issue #4.

(Jan-06-2020)

# v1.05
- Fix a custom `kdf_iter` that was not handled correctly when decrypting.
  Thanks to Vincent &lt;vincentxueios at gmail.com&gt; (Feb-15-2019)


# v1.04
- memcmp() typically does not execute in constant time. Hence timing
  attack can be performed while comparing hmacs. Thanks to Scott
  Arciszewski for pointing it out. Fixes issue #1

(Jan-25-2016)

# v1.03
- Uses less memory, removed duplicate code. Lots of Code cleanup.

- Updated RNCryptor-C link

(Jun-01-2015)

# v1.02
- Implemented function
  `rncryptorc_encrypt_data_with_password_with_salts_and_iv()` so that
  caller can pass encryption salt, hmac salt and iv.

- Implemented function `rncryptorc_encrypt_data_with_key_iv()` so that
  caller can pass IV.

- Implemented unit tests for testing all of the RNCryptor’s v3 test
  vectors.

(May-31-2015)

# v1.01
- Released May-27-2015
