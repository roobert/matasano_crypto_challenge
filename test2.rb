#!/usr/bin/env ruby
#encoding=utf-8

require 'openssl'

require_relative 'lib/matasano_challenge.rb'

include MatasanoChallenge

input = Convert.ascii_to_bytes(File.open("data/10/expected_message.txt").read)

message = MatasanoChallenge.aes_encrypt_with_random_key_and_random_mode(input)

ap message
#ap message[:message]

#puts 'test'

# MatasanoChallenge.detect_aes_mode(message[:message])
