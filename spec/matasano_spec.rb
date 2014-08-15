#!/usr/bin/env ruby

require 'openssl'
require 'minitest/pride'
require 'minitest/autorun'
#require 'turn'
require 'load_path'
require 'ap'

LoadPath.configure do
  add parent_directory('lib', up: 1)
end

require 'matasano_challenge'

include MatasanoChallenge

describe '0: helpers to convert data' do

  # apparently we want *_to_hex to output a string of doubles rather than an array of hex..
  #hex   = ["0x61", "0x62", "0x63", "0x64", "0x65", "0x41", "0x42", "0x43", "0x44", "0x45"]

  # the above are all equivalent
  ascii  = 'abcdeABCDE'
  bytes  = [97, 98, 99, 100, 101, 65, 66, 67, 68, 69]
  hex    = '61626364654142434445'
  base64 = 'YWJjZGVBQkNERQ=='

  it '#bytes_to_ascii' do
    Convert.bytes_to_ascii(bytes).must_equal ascii
  end

  it '#ascii_to_bytes' do
    Convert.ascii_to_bytes(ascii).must_equal bytes
  end

  it '#bytes_to_hex' do
    Convert.bytes_to_hex(bytes).must_equal hex
  end

  it '#hex_to_bytes' do
    Convert.hex_to_bytes(hex).must_equal bytes
  end

  it '#bytes_to_base64' do
    Convert.bytes_to_base64(bytes).must_equal base64
  end

  it '#base64_to_bytes' do
    Convert.base64_to_bytes(base64).must_equal bytes
  end
end

# // ------------------------------------------------------------
#
# 1. Convert hex to base64 and back.
#
# The string:
#
#   49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
#
# should produce:
#
#   SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
#
# Now use this code everywhere for the rest of the exercises. Here's a
# simple rule of thumb:
#
#   Always operate on raw bytes, never on encoded strings. Only use hex
#   and base64 for pretty-printing.

# NOTE

# hex is used as human friendly representation of binary-coded values

# Each hexadecimal digit represents four binary digits (bits).
# One hexadecimal digit represents a nibble, which is half of an octet or byte (8 bits).

# For example, byte values can range from 0 to 255 (decimal), but may be more conveniently represented as two hexadecimal digits in the range 00 to FF.

# first problem
describe '1: should convert hex to base64 and back' do

  hex              = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
  base64           = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
  expected_message = "I'm killing your brain like a poisonous mushroom"

  it '#hex_to_base64' do
    Convert.hex_to_base64(hex).must_equal base64
  end

  it '#base64_to_hex' do
    Convert.base64_to_hex(base64).must_equal hex
  end

  it "message: #{expected_message}" do
    message = Convert.bytes_to_ascii(Convert.hex_to_bytes(hex))

    message.must_equal expected_message
  end
end

# // ------------------------------------------------------------
#
# 2. Fixed XOR
#
# Write a function that takes two equal-length buffers and produces
# their XOR sum.
#
# The string:
#
#  1c0111001f010100061a024b53535009181c
#
# ... after hex decoding, when xor'd against:
#
#  686974207468652062756c6c277320657965
#
# ... should produce:
#
#  746865206b696420646f6e277420706c6179

# NOTE
#
# The key insight with XORing bits is that in the result, all bits that
# are *different* are 1, and all bits that are the *same* are 0

describe '2: fixed XOR' do
  ascii            = '1c0111001f010100061a024b53535009181c'
  xor              = '686974207468652062756c6c277320657965'
  expected_result  = '746865206b696420646f6e277420706c6179'
  expected_message = "the kid don't play"

  it '#xor' do
    string_a      = Convert.hex_to_bytes(ascii)
    string_b      = Convert.hex_to_bytes(xor)
    result        = Convert.xor(string_a, string_b)
    packed_result = Convert.bytes_to_hex(result)

    #puts
    #puts "  string_a unpacked hex: #{string_a}"
    #puts "  string_b unpacked hex: #{string_b}"
    #puts
    #puts "  xor result: #{result}"
    #puts
    #puts "  packed result as hex: #{packed_result}"
    #puts

    packed_result.must_equal expected_result
  end

  it "message: #{expected_message}" do
    string_a = Convert.hex_to_bytes(ascii)
    string_b = Convert.hex_to_bytes(xor)
    message  = Convert.bytes_to_ascii(Convert.xor(string_a, string_b))

    message.must_equal expected_message
  end
end

# // ------------------------------------------------------------
#
# 3. Single-character XOR Cipher
#
# The hex encoded string:
#
#       1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
#
# ... has been XOR'd against a single character. Find the key, decrypt
# the message.
#
# Write code to do this for you. How? Devise some method for "scoring" a
# piece of English plaintext. (Character frequency is a good metric.)
# Evaluate each output and choose the one with the best score.
#
# Tune your algorithm until this works.

describe '3. Single-character XOR Cipher' do

  ascii            = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
  expected_message = "Cooking MC's like a pound of bacon"

  it '#find_most_likely_single_char_xor_key' do
    MatasanoChallenge.find_most_likely_single_char_xor_key(Convert.hex_to_bytes(ascii))[0].must_equal expected_message
  end

  it "message: #{expected_message}" do
    MatasanoChallenge.find_most_likely_single_char_xor_key(Convert.hex_to_bytes(ascii))[0].must_equal expected_message
  end
end

# // ------------------------------------------------------------
#
# 4. Detect single-character XOR
#
# One of the 60-character strings at:
#
#   https://gist.github.com/3132713
#
# has been encrypted by single-character XOR. Find it. (Your code from
# #3 should help.)

describe '4. Detect single-character XOR' do

  text = File.open('data/4/gistfile1.txt', 'r').read
  expected_message = "Now that the party is jumping\n"

  it '#find_most_likely_in_text' do
    MatasanoChallenge.find_most_likely_in_text(text)[0].must_equal expected_message
  end

  it "message: #{expected_message}" do
    MatasanoChallenge.find_most_likely_in_text(text)[0].must_equal expected_message
  end
end

# // ------------------------------------------------------------
#
# 5. Repeating-key XOR Cipher
#
# Write the code to encrypt the string:
#
#   Burning 'em, if you ain't quick and nimble
#   I go crazy when I hear a cymbal
#
# Under the key "ICE", using repeating-key XOR. It should come out to:
#
#   0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
#
# Encrypt a bunch of stuff using your repeating-key XOR function. Get a
# feel for it.
#

describe '5. Repeating-key XOR Cipher' do

  text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

  expected_result = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

  key = 'ICE'

  it '#xor_repeat_key' do
    Convert.bytes_to_hex(MatasanoChallenge.xor_repeat_key(Convert.ascii_to_bytes(text), Convert.ascii_to_bytes(key))).must_equal expected_result
  end

  it "expected result of \"#{text}\" repeatedly XOR'd with \"ICE\": #{expected_result}" do
    Convert.bytes_to_hex(MatasanoChallenge.xor_repeat_key(Convert.ascii_to_bytes(text), Convert.ascii_to_bytes(key))).must_equal expected_result
  end
end

# // ------------------------------------------------------------
#
# 6. Break repeating-key XOR
#
# The buffer at the following location:
#
#  https://gist.github.com/3132752
#
# is base64-encoded repeating-key XOR. Break it.
#
# Here's how:
#
# a. Let KEYSIZE be the guessed length of the key; try values from 2 to
# (say) 40.
#
# b. Write a function to compute the edit distance/Hamming distance
# between two strings. The Hamming distance is just the number of
# differing bits. The distance between:
#
#   this is a test
#
# and:
#
#   wokka wokka!!!
#
# is 37.
#
# c. For each KEYSIZE, take the FIRST KEYSIZE worth of bytes, and the
# SECOND KEYSIZE worth of bytes, and find the edit distance between
# them. Normalize this result by dividing by KEYSIZE.
#
# d. The KEYSIZE with the smallest normalized edit distance is probably
# the key. You could proceed perhaps with the smallest 2-3 KEYSIZE
# values. Or take 4 KEYSIZE blocks instead of 2 and average the
# distances.
#
# e. Now that you probably know the KEYSIZE: break the ciphertext into
# blocks of KEYSIZE length.
#
# f. Now transpose the blocks: make a block that is the first byte of
# every block, and a block that is the second byte of every block, and
# so on.
#
# g. Solve each block as if it was single-character XOR. You already
# have code to do this.
#
# e. For each block, the single-byte XOR key that produces the best
# looking histogram is the repeating-key XOR key byte for that
# block. Put them together and you have the key.

describe '6. Repeating-key XOR Cipher' do

  string_a                  = 'this is a test'
  string_b                  = 'wokka wokka!!!'
  expected_hamming_distance = 37

  text            = File.open('data/6/base64_repeating_key_xor.txt', 'r').read
  expected_result = File.open('data/6/expected_result.txt', 'r').read.chomp

  text_bytes = Convert.hex_to_bytes(Convert.base64_to_hex(text.gsub("\n", '')))

  min_key_size = 2
  max_key_size = 40

  it '#base64_to_ascii' do
  end

  it '#calculate_key_size' do
  end

  it '#calculate_hamming_distance' do
    MatasanoChallenge.calculate_hamming_distance(
      Convert.ascii_to_bytes(string_a),
      Convert.ascii_to_bytes(string_b)
    ).must_equal expected_hamming_distance
  end

  it '#break_repeating_key_xor_cipher' do
    MatasanoChallenge.break_repeating_key_xor_cipher(text_bytes, min_key_size, max_key_size).chomp.must_equal expected_result
  end
end

# // ------------------------------------------------------------
#
# 7. AES in ECB Mode
#
# The Base64-encoded content at the following location:
#
#     https://gist.github.com/3132853
#
# Has been encrypted via AES-128 in ECB mode under the key
#
#     "YELLOW SUBMARINE".
#
# (I like "YELLOW SUBMARINE" because it's exactly 16 bytes long).
#
# Decrypt it.
#
# Easiest way:
#
# Use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
#
# // ------------------------------------------------------------

describe '7. AES in ECB Mode' do

  text = File.open('data/7/gistfile1.txt', 'r').read
  key  = 'YELLOW SUBMARINE'

  expected_result = File.open('data/7/expected_result.txt', 'r').read.chomp

  text_plain = Convert.bytes_to_ascii(Convert.hex_to_bytes(Convert.base64_to_hex(text.gsub("\n", ''))))

  it '#aes_decrypt' do
    MatasanoChallenge.aes_decrypt(text_plain, key).must_equal expected_result
  end
end

# 8. Detecting ECB
#
# At the following URL are a bunch of hex-encoded ciphertexts:
#
#    https://gist.github.com/3132928
#
# One of them is ECB encrypted. Detect it.
#
# Remember that the problem with ECB is that it is stateless and
# deterministic; the same 16 byte plaintext block will always produce
# the same 16 byte ciphertext.
#
# // ------------------------------------------------------------

describe '8. Detecting ECB' do

  text_plain = File.open('data/8/gistfile1.txt', 'r').read

  expected_result = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a\n"

  it '#detect_ecb' do
    MatasanoChallenge.detect_ecb(text_plain)[0][:cipher_text].must_equal expected_result
  end
end

# // ------------------------------------------------------------
#
# 9. Implement PKCS#7 padding
#
# Pad any block to a specific block length, by appending the number of
# bytes of padding to the end of the block. For instance,
#
#   "YELLOW SUBMARINE"
#
# padded to 20 bytes would be:
#
#   "YELLOW SUBMARINE\x04\x04\x04\x04"
#
# The particulars of this algorithm are easy to find online.

# PKCS#7 RFC / padding section: http://tools.ietf.org/html/rfc2315#section-10.3

describe '9. Implement PKCS#7 padding' do

  text_a = 'YELLOW SUBMARINE'

  text_a_length = 20

  expected_result_a = "YELLOW SUBMARINE\x04\x04\x04\x04"

  text_b = 'TEST'

  text_b_length = 30

  expected_result_b =
    "TEST\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a"

  text_c = 'TEST FULL BLOCK!'

  text_c_length = 16

  expected_result_c =
    "TEST FULL BLOCK!\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"

  it '#pad_block test_a' do
    Convert.bytes_to_ascii(
      MatasanoChallenge.pad_block(Convert.ascii_to_bytes(text_a), text_a_length))
      .must_equal expected_result_a
  end

  it '#pad_block test_b' do
    Convert.bytes_to_ascii(
      MatasanoChallenge.pad_block(Convert.ascii_to_bytes(text_b), text_b_length))
      .must_equal expected_result_b
  end

  it '#pad_block test_c' do
    Convert.bytes_to_ascii(
      MatasanoChallenge.pad_block(Convert.ascii_to_bytes(text_c), text_c_length))
      .must_equal expected_result_c
  end
end

# // ------------------------------------------------------------
#
# 10. Implement CBC Mode
#
# In CBC mode, each ciphertext block is added to the next plaintext
# block before the next call to the cipher core.
#
# The first plaintext block, which has no associated previous ciphertext
# block, is added to a "fake 0th ciphertext block" called the IV.
#
# Implement CBC mode by hand by taking the ECB function you just wrote,
# making it encrypt instead of decrypt (verify this by decrypting
# whatever you encrypt to test), and using your XOR function from
# previous exercise.
#
# DO NOT CHEAT AND USE OPENSSL TO DO CBC MODE, EVEN TO VERIFY YOUR
# RESULTS. What's the point of even doing this stuff if you aren't going
# to learn from it?
#
# The buffer at:
#
#     https://gist.github.com/3132976
#
# is intelligible (somewhat) when CBC decrypted against "YELLOW
# SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

describe '10. Implement CBC Mode' do

  # need 128 bit key and 128 bit iv, the result will  be padded (16 bytes)
  block_size = 64
  message    = 'Hello, this is my test message!'
  iv         = "01" * 16
  key        = 'X' * 16

  expected_result =
    'qotF5Mi9i+eTqzagtMTZHJj0/05LUoK1iM75hyHiQ1ARDnMJDuEvBcpeqmyizz8i'


  test_key = "YELLOW SUBMARINE"
  test_iv  = "0" * 16
  test_message = File.open('data/10/gistfile1.txt', 'r').read


  it '#aes_decrypt' do
    encrypted_message = MatasanoChallenge.aes_encrypt(message, key)
    MatasanoChallenge.aes_decrypt(encrypted_message, key).must_equal message
  end

  it '#cbc_encrypt' do
    Convert.bytes_to_base64(
      MatasanoChallenge.cbc_encrypt(
        MatasanoChallenge.pad_block(Convert.ascii_to_bytes(message), 16), block_size,
        Convert.hex_to_bytes(iv), key
      )
    ).must_equal expected_result
  end

  it '#cbc_decrypt' do
    Convert.bytes_to_ascii(
      MatasanoChallenge.cbc_decrypt(
        Convert.base64_to_bytes(expected_result), block_size,
        Convert.hex_to_bytes(iv), key
      )
    ).must_equal message
  end

  it '#cbc_decrypt matasano test message' do
    Convert.bytes_to_ascii(
      MatasanoChallenge.cbc_decrypt(
        Convert.base64_to_bytes(test_message.gsub("\n", '')), block_size,
        Convert.ascii_to_bytes(test_iv), test_key
      )
    ).must_equal message
  end
end

# // ------------------------------------------------------------
#
# 11. Write an oracle function and use it to detect ECB.
#
# Now that you have ECB and CBC working:
#
# Write a function to generate a random AES key; that's just 16 random
# bytes.
#
# Write a function that encrypts data under an unknown key --- that is,
# a function that generates a random key and encrypts under it.
#
# The function should look like:
#
# encryption_oracle(your-input)
#  => [MEANINGLESS JIBBER JABBER]
#
# Under the hood, have the function APPEND 5-10 bytes (count chosen
# randomly) BEFORE the plaintext and 5-10 bytes AFTER the plaintext.
#
# Now, have the function choose to encrypt under ECB 1/2 the time, and
# under CBC the other half (just use random IVs each time for CBC). Use
# rand(2) to decide which to use.
#
# Now detect the block cipher mode the function is using each time.


# // ------------------------------------------------------------
#
# 12. Byte-at-a-time ECB decryption, Full control version
#
# Copy your oracle function to a new function that encrypts buffers
# under ECB mode using a consistent but unknown key (for instance,
# assign a single random key, once, to a global variable).
#
# Now take that same function and have it append to the plaintext,
# BEFORE ENCRYPTING, the following string:
#
#   Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
#   aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
#   dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
#   YnkK
#
# SPOILER ALERT: DO NOT DECODE THIS STRING NOW. DON'T DO IT.
#
# Base64 decode the string before appending it. DO NOT BASE64 DECODE THE
# STRING BY HAND; MAKE YOUR CODE DO IT. The point is that you don't know
# its contents.
#
# What you have now is a function that produces:
#
#   AES-128-ECB(your-string || unknown-string, random-key)
#
# You can decrypt "unknown-string" with repeated calls to the oracle
# function!
#
# Here's roughly how:
#
# a. Feed identical bytes of your-string to the function 1 at a time ---
# start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the
# block size of the cipher. You know it, but do this step anyway.
#
# b. Detect that the function is using ECB. You already know, but do
# this step anyways.
#
# c. Knowing the block size, craft an input block that is exactly 1 byte
# short (for instance, if the block size is 8 bytes, make
# "AAAAAAA"). Think about what the oracle function is going to put in
# that last byte position.
#
# d. Make a dictionary of every possible last byte by feeding different
# strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB",
# "AAAAAAAC", remembering the first block of each invocation.
#
# e. Match the output of the one-byte-short input to one of the entries
# in your dictionary. You've now discovered the first byte of
# unknown-string.
#
# f. Repeat for the next byte.


# // ------------------------------------------------------------
#
# 13. ECB cut-and-paste
#
# Write a k=v parsing routine, as if for a structured cookie. The
# routine should take:
#
#    foo=bar&baz=qux&zap=zazzle
#
# and produce:
#
# {
#     foo: 'bar',
#     baz: 'qux',
#     zap: 'zazzle'
#
# }
#
# (you know, the object; I don't care if you convert it to JSON).
#
# Now write a function that encodes a user profile in that format, given
# an email address. You should have something like:
#
#   profile_for("foo@bar.com")
#
# and it should produce:
#
# {
#     email: 'foo@bar.com',
#     uid: 10,
#     role: 'user'
#
# }
#
# encoded as:
#
#   email=foo@bar.com&uid=10&role=user
#
# Your "profile_for" function should NOT allow encoding metacharacters
# (& and =). Eat them, quote them, whatever you want to do, but don't
# let people set their email address to "foo@bar.com&role=admin".
#
# Now, two more easy functions. Generate a random AES key, then:
#
#  (a) Encrypt the encoded user profile under the key; "provide" that
#  to the "attacker".
#
#  (b) Decrypt the encoded user profile and parse it.
#
# Using only the user input to profile_for() (as an oracle to generate
# "valid" ciphertexts) and the ciphertexts themselves, make a role=admin
# profile.


# // ------------------------------------------------------------
#
# 14. Byte-at-a-time ECB decryption, Partial control version
#
# Take your oracle function from #12. Now generate a random count of
# random bytes and prepend this string to every plaintext. You are now
# doing:
#
#   AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
#
# Same goal: decrypt the target-bytes.
#
# What's harder about doing this?
#
# How would you overcome that obstacle? The hint is: you're using
# all the tools you already have; no crazy math is required.
#
# Think about the words "STIMULUS" and "RESPONSE".


# // ------------------------------------------------------------
#
# 15. PKCS#7 padding validation
#
# Write a function that takes a plaintext, determines if it has valid
# PKCS#7 padding, and strips the padding off.
#
# The string:
#
#     "ICE ICE BABY\x04\x04\x04\x04"
#
# has valid padding, and produces the result "ICE ICE BABY".
#
# The string:
#
#     "ICE ICE BABY\x05\x05\x05\x05"
#
# does not have valid padding, nor does:
#
#      "ICE ICE BABY\x01\x02\x03\x04"
#
# If you are writing in a language with exceptions, like Python or Ruby,
# make your function throw an exception on bad padding.


# // ------------------------------------------------------------
#
# 16. CBC bit flipping
#
# Generate a random AES key.
#
# Combine your padding code and CBC code to write two functions.
#
# The first function should take an arbitrary input string, prepend the
# string:
#         "comment1=cooking%20MCs;userdata="
# and append the string:
#     ";comment2=%20like%20a%20pound%20of%20bacon"
#
# The function should quote out the ";" and "=" characters.
#
# The function should then pad out the input to the 16-byte AES block
# length and encrypt it under the random AES key.
#
# The second function should decrypt the string and look for the
# characters ";admin=true;" (or, equivalently, decrypt, split the string
# on ;, convert each resulting string into 2-tuples, and look for the
# "admin" tuple. Return true or false based on whether the string exists.
#
# If you've written the first function properly, it should not be
# possible to provide user input to it that will generate the string the
# second function is looking for.
#
# Instead, modify the ciphertext (without knowledge of the AES key) to
# accomplish this.
#
# You're relying on the fact that in CBC mode, a 1-bit error in a
# ciphertext block:
#
# * Completely scrambles the block the error occurs in
#
# * Produces the identical 1-bit error (/edit) in the next ciphertext
#  block.
#
# Before you implement this attack, answer this question: why does CBC
# mode have this property?

# // ------------------------------------------------------------)
