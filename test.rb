#!/usr/bin/env ruby
#encoding=utf-8

require 'openssl'

require_relative 'lib/matasano_challenge.rb'

include MatasanoChallenge

block_size = 16
key        = "YELLOW SUBMARINE"
iv         = "0" * 16
message    = File.open('data/10/gistfile1.txt', 'r').read

ap message.gsub!("\n", '')

puts Convert.bytes_to_ascii(
       MatasanoChallenge.cbc_decrypt(
         Convert.base64_to_bytes(message),
         block_size,
         Convert.hex_to_bytes(iv),
         key
       )
     )
