#!/usr/bin/env ruby

require 'openssl'
require "minitest/pride"
require "minitest/autorun"
#require "turn"
require "load_path"
require "ap"

LoadPath.configure do
  add parent_directory('lib', up: 1)
end

require "matasano_challenge"

include MatasanoChallenge

describe "0: helpers to convert data" do

  # apparently we want *_to_hex to output a string of doubles rather than an array of hex..
  #hex   = ["0x61", "0x62", "0x63", "0x64", "0x65", "0x41", "0x42", "0x43", "0x44", "0x45"]

  # the above are all equivalent
  ascii  = "abcdeABCDE"
  bytes  = [97, 98, 99, 100, 101, 65, 66, 67, 68, 69]
  hex    = "61626364654142434445"
  base64 = "YWJjZGVBQkNERQ=="

  it "#bytes_to_ascii" do
    Convert.bytes_to_ascii(bytes).must_equal ascii
  end

  it "#ascii_to_bytes" do
    Convert.ascii_to_bytes(ascii).must_equal bytes
  end

  it "#bytes_to_hex" do
    Convert.bytes_to_hex(bytes).must_equal hex
  end

  it "#hex_to_bytes" do
    Convert.hex_to_bytes(hex).must_equal bytes
  end

  it "#bytes_to_base64" do
    Convert.bytes_to_base64(bytes).must_equal base64
  end

  it "#base64_to_bytes" do
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
describe "1: should convert hex to base64 and back" do

  hex              = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
  base64           = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
  expected_message = "I'm killing your brain like a poisonous mushroom"

  it "#hex_to_base64" do
    Convert.hex_to_base64(hex).must_equal base64
  end

  it "#base64_to_hex" do
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

describe "2: fixed XOR" do
  ascii            = "1c0111001f010100061a024b53535009181c"
  xor              = "686974207468652062756c6c277320657965"
  expected_result  = "746865206b696420646f6e277420706c6179"
  expected_message = "the kid don't play"

  it "#xor" do
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

describe "3. Single-character XOR Cipher" do

  ascii            = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
  expected_message = "Cooking MC's like a pound of bacon"

  it "#find_most_likely_single_char_xor_key" do
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

describe "4. Detect single-character XOR" do

  text = File.open("data/4/gistfile1.txt", "r").read
  expected_message = "Now that the party is jumping\n"

  it "#find_most_likely_in_text" do
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

describe "5. Repeating-key XOR Cipher" do

  text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

  expected_result = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

  key = "ICE"

  it "#xor_repeat_key" do
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

describe "6. Repeating-key XOR Cipher" do

  string_a                  = "this is a test"
  string_b                  = "wokka wokka!!!"
  expected_hamming_distance = 37

  text            = File.open('data/6/base64_repeating_key_xor.txt', 'r').read
  expected_result = File.open('data/6/expected_result.txt', 'r').read.chomp

  text_bytes = Convert.hex_to_bytes(Convert.base64_to_hex(text.gsub("\n", '')))

  min_key_size = 2
  max_key_size = 40

  it "#base64_to_ascii" do
  end

  it "#calculate_key_size" do
  end

  it "#calculate_hamming_distance" do
    MatasanoChallenge.calculate_hamming_distance(
      Convert.ascii_to_bytes(string_a),
      Convert.ascii_to_bytes(string_b)
    ).must_equal expected_hamming_distance
  end

  it "#break_repeating_key_xor_cipher" do
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

describe "7. AES in ECB Mode" do

  text = File.open('data/7/gistfile1.txt', 'r').read
  key  = "YELLOW SUBMARINE"

  expected_result = File.open('data/7/expected_result.txt', 'r').read.chomp

  text_plain = Convert.bytes_to_ascii(Convert.hex_to_bytes(Convert.base64_to_hex(text.gsub("\n", ''))))

  it "#aes_decipher" do
    MatasanoChallenge.aes_decipher(text_plain, key).must_equal expected_result
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

describe "8. Detecting ECB" do

  text_plain = File.open('data/8/gistfile1.txt', 'r').read

  expected_result = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a\n"

  it "#detect_ecb" do
    MatasanoChallenge.detect_ecb(text_plain)[0][:cipher_text].must_equal expected_result
  end
end
