#!/usr/bin/env ruby

require 'pp'
require 'base64'

# A String object holds and manipulates an arbitrary sequence of bytes, typically representing characters. String objects may be created using String::new or as literals.

# formatting printing of strings: http://www.ruby-doc.org/core-2.1.2/Kernel.html -> format

module MatasanoChallenge
  module Convert
    def self.hex_to_base64(ascii)
      puts "hex_to_base64, input: #{ascii.inspect}" if $DEBUG

      output = bytes_to_base64(hex_to_bytes(ascii))

      puts "hex_to_base64, output: #{output.inspect}" if $DEBUG

      output
    end

    def self.base64_to_hex(ascii)
      puts "base64_to_hex, input: #{ascii.inspect}" if $DEBUG

      output = bytes_to_hex(base64_to_bytes(ascii))

      puts "base64_to_hex, output: #{output.inspect}" if $DEBUG

      output
    end

    # => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    BASE64_ENCODING_TABLE=[ ('A'..'Z'), ('a'..'z'), (0..9), ['+', '/'] ].map { |range| range.to_a }.flatten.join

    # bytes  -> ascii
    # ascii  -> bytes
    # bytes  -> base64
    # base64 -> bytes
    # bytes  -> hex
    # hex    -> bytes

    # NOTE: ascii == string == chars

    # bytes_to_ascii
    #
    # bytes in:  an array of ints that represent ascii bytes
    # ascii out: string
    def self.bytes_to_ascii(bytes)
      puts "bytes_to_ascii, input: #{bytes.inspect}" if $DEBUG

      output = bytes.map { |byte| byte.chr }.join

      puts "bytes_to_ascii, output: #{output.inspect}" if $DEBUG

      output
    end

    # ascii_to_bytes
    #
    # ascii in:  string
    # bytes out:  an array of ints that represent ascii bytes
    def self.ascii_to_bytes(ascii)
      puts "ascii_to_bytes, input: #{ascii.inspect}" if $DEBUG

      output = ascii.each_char.map { |char| char.ord }

      puts "ascii_to_bytes, output: #{output.inspect}" if $DEBUG

      output
    end

    # bytes_to_base64
    #
    # bytes in: an array of ints that represent ascii bytes
    # ascii out: string
    def self.bytes_to_base64(bytes)

      # method:

      # take first 3 ascii values and convert into one 24 bit binary string, e.g:
      # A = 1 = 00000001
      # B = 2 = 00000010
      # C = 3 = 00000011

      # then mash them together, e.g: 
      # 000000010000001000000011

      # break the 24bit string down into 4*6 bit strings, e.g:
      # 000000
      # 010000
      # 001000
      # 000011

      # convert each 6bit string to a base 10 int and use the
      # value as the index to lookup a character from the 
      # BASE64 encoding table

      # implimentation:

      # convert ascii bytes into binary then join to create one large binary string
      # NOTE: 0 padding!
      #binary = bytes.map { |byte| "%08b" % byte }.join

      # take each 6 bit group and convert to decimal and use it as the index
      # for the binary encoding table
      #binary.scan(/....../).map { |index| BASE64_ENCODING_TABLE[index.to_i(2)] }.join

      puts "bytes_to_base64, input: #{bytes.inspect}" if $DEBUG

      output = Base64.strict_encode64(bytes_to_ascii(bytes))

      puts "bytes_to_base64, output: #{output.inspect}" if $DEBUG

      output
    end

    # The '==' sequence indicates that the last group contained only one byte, and '=' indicates that it contained two bytes. The example below illustrates how truncating the input of the whole of the above quote changes the output padding:

    def self.base64_to_bytes(ascii)
      # NOTE: 6bit binary! 
      #binary = ascii.each_char.map { |char| "%06b" % BASE64_ENCODING_TABLE.index(char) }.join

      #binary.scan(/......../).map { |byte| byte.to_i(2) }

      puts "base64_to_bytes, input: #{ascii.inspect}" if $DEBUG

      output = ascii_to_bytes(Base64.strict_decode64(ascii))

      puts "base64_to_bytes, output: #{output.inspect}" if $DEBUG

      output
    end

    def self.bytes_to_hex(bytes)
      # output an array..
      #bytes.map { |byte| "%#x" % byte } 

      puts "bytes_to_hex, input: #{bytes.inspect}" if $DEBUG

      # FIXME? assumes hex is always going to be a string of doubles rather than an array of hex strings?!
      output = bytes.map { |byte| "%02x" % byte }.join

      puts "bytes_to_hex, output: #{output.inspect}" if $DEBUG

      output
    end

    # FIXME: this is really broken and should allow values represented by strings that are more or
    #        less than two bytes
    def self.hex_to_bytes(string)

      puts "hex_to_bytes, input: #{string.inspect}" if $DEBUG

      # convert string of hex doubles to an array of decimal values which represent ascii values
      # each double represents a numeric value
      output = string.scan(/../).map do |double|
        double.to_i(16)
      end

      puts "hex_to_bytes, output: #{output.inspect}" if $DEBUG

      output
    end

    # returns array of bytes
    def self.xor(string_a_bytes, string_b_bytes)

      puts "xor, a_input: #{string_a_bytes.inspect}" if $DEBUG
      puts "xor, b_input: #{string_b_bytes.inspect}" if $DEBUG

      output = string_a_bytes.zip(string_b_bytes).map { |pair| pair[0].to_i ^ pair[1].to_i  }
#      string_a_bytes.each_with_index.map do |byte, index|
#        if byte.nil?  or string_b_bytes[index].nil?
#          nil
#        else
#          byte ^ string_b_bytes[index]
#        end
#      end

      puts "xor, output: #{output.inspect}" if $DEBUG

      output
    end
  end

  # given a string of bytes, find the most likely string of bytes that XORs to produce a sentence
  def self.find_most_likely_single_char_xor_key(string_bytes)

    # build up a string of characters to test against
    chars = []
    chars << ('a'..'z').to_a
    chars << ('A'..'Z').to_a
    chars << ('0'..'9').to_a
    # added for problem 6:
    chars << [ '\'', '.', ' ', '!', '?', '@', '"', '$', '\(', '\)', '-', '=' '#', '%', '^', '*', '[', ']', ':', ';', '~', '|' '\'']
    chars = chars.flatten!.join

    # FIXME: refactor
    popularity_table = {
      Convert.ascii_to_bytes('a')[0] => 11.602, Convert.ascii_to_bytes('b')[0] => 4.702,  Convert.ascii_to_bytes('c')[0] => 3.511,
      Convert.ascii_to_bytes('d')[0] => 2.670,  Convert.ascii_to_bytes('e')[0] => 2.000,  Convert.ascii_to_bytes('f')[0] => 3.779,
      Convert.ascii_to_bytes('g')[0] => 1.950,  Convert.ascii_to_bytes('h')[0] => 7.232,  Convert.ascii_to_bytes('i')[0] => 6.286,
      Convert.ascii_to_bytes('j')[0] => 0.631,  Convert.ascii_to_bytes('k')[0] => 0.690,  Convert.ascii_to_bytes('l')[0] => 2.705,
      Convert.ascii_to_bytes('m')[0] => 4.374,  Convert.ascii_to_bytes('n')[0] => 2.365,  Convert.ascii_to_bytes('o')[0] => 6.264,
      Convert.ascii_to_bytes('p')[0] => 2.545,  Convert.ascii_to_bytes('q')[0] => 0.173,  Convert.ascii_to_bytes('r')[0] => 1.653,
      Convert.ascii_to_bytes('s')[0] => 7.755,  Convert.ascii_to_bytes('t')[0] => 16.671, Convert.ascii_to_bytes('u')[0] => 1.487,
      Convert.ascii_to_bytes('v')[0] => 0.619,  Convert.ascii_to_bytes('w')[0] => 6.661,  Convert.ascii_to_bytes('x')[0] => 0.005,
      Convert.ascii_to_bytes('y')[0] => 1.620,  Convert.ascii_to_bytes('z')[0] => 0.050,  Convert.ascii_to_bytes(' ')[0] => 20,
      Convert.ascii_to_bytes('.')[0] => 0.500,  Convert.ascii_to_bytes(',')[0] => 0.500,  Convert.ascii_to_bytes('!')[0] => 0.500,
      Convert.ascii_to_bytes('\'')[0] => 0.500, Convert.ascii_to_bytes('!')[0] => 0.500,  Convert.ascii_to_bytes('?')[0] => 0.500,
    }

    chars_in_bytes = Convert.ascii_to_bytes chars

    result_hash = {}

    chars_in_bytes.each do |char|

      # xor bytes ...
      bytes = []

      string_bytes.each { |byte| bytes.push(byte ^ char) }

      message = bytes.pack('C*')
      score   = 0

      # ok so calculating score based on frequency table seems to be a much
      # more accurate method than the stuff below
      bytes.to_a.each { |b| score += popularity_table[b] if popularity_table.has_key?(b) }

      # if message begins with a capital letter
      score += 2 if message =~ /^[A-Z][a-z]+ /

      # if the message contains a space
      score += 1 if message =~ / /

      # if there's punctuation at the end of message
      score += 1 if message =~ /\.$/

      ## if there's a comma in the message
      ##score += 1 if message =~ /,/

      # if there's an apostrophe in the message
      ##score += 1 if message =~ /'/

      # try to improve detection..

      # if message contains a word with a capital letter..
      #score += 1 if message =~ /[A-Z][a-z]+ /

      # word detection
      score += 2 if message =~ / \w /

      # if message contains common stuff
      score += 3 if message =~ /th/i
      score += 3 if message =~ /oo/i
      score += 3 if message =~ /ing/i
      score += 3 if message =~ /er/i
      score += 3 if message =~ /ly/i
      score += 3 if message =~ /ee/i

      score += 5 if message =~ /the/i
      score += 5 if message =~ /and/i

      result_hash[message] = [score, Convert.bytes_to_ascii([char])]
    end

    # returns ["string", [score, "<char>"]]
    result_hash.max_by{|k,v| v[0]}
  end

  def self.find_most_likely_in_text(text)
    # find most likely key/text for each line in text
    results = text.each_line.map { |line| find_most_likely_single_char_xor_key(Convert.hex_to_bytes(line)) }

    # sort by score and pic highest result
    results.max_by{|k,v| v[0]}
  end

  def self.xor_repeat_key(secret_bytes, key_bytes)
    repeat_key = [].fill(0, secret_bytes.length) { |index| key_bytes.rotate![2] }

    Convert.xor(secret_bytes, repeat_key)
  end

  def self.calculate_hamming_distance(string_a_bytes, string_b_bytes)
    Convert.xor(string_a_bytes, string_b_bytes).map { |byte| "%b" % byte }.join.delete('0').length
  end

  def self.calculate_key_size(text_bytes, min_keysize, max_keysize, debug: false)
    results = (min_keysize..max_keysize).each_with_index.map do |keylength|

      hamming_distance = \
        MatasanoChallenge.calculate_hamming_distance(
          text_bytes[0..keylength],
          text_bytes[0..keylength - 1]
        )

      result = [ keylength, keylength - 1, hamming_distance ]

      print "keylengths: %3i, %3i - hamming_distance: %i\n" % result if debug

      result
    end

    # return suspected keyesize where keysize == keysize -1 (rather than keysize)
    results.min_by { |result| result[2] }[1]
  end

  def self.break_repeating_key_xor_cipher(text_bytes, min_key_size, max_key_size)

    # FIXME: add debug stuff to this..
    keysize = MatasanoChallenge.calculate_key_size(text_bytes, min_key_size, max_key_size)

    chunks = text_bytes.each_slice(keysize).to_a

    original_number_of_chunks = chunks.length
    #puts "chunks.length: #{chunks.length}"

    # transpose ...
    blocks = []
    index  = 0

    # pretty certain this does what it should... (requires: key length)
    until chunks.empty? do

      # create block
      blocks[index] = []

      # fill block with first byte of every chunk
      chunks.each do |chunk|
        if chunk.empty?
          chunks.delete([])
        else
          blocks[index].push chunk.shift
        end
      end

      index += 1
    end

    most_likely_single_char_xor_keys = ""

    begin
      blocks.each_with_index do |block, index|
        #puts "%2i - %s" % [ index, block.join ]
        most_likely_single_char_xor_keys += MatasanoChallenge.find_most_likely_single_char_xor_key(block)[1][1]
      end
    rescue => e
      puts "error: #{e}"
    end

    # FIXME: why am i getting an extra character??
    most_likely_single_char_xor_keys = most_likely_single_char_xor_keys.chomp("'")

    #puts "most likely key: #{most_likely_single_char_xor_keys}"

    # FIXME: this sucks.. work out how to make repeating key of correct length..
    key = most_likely_single_char_xor_keys * original_number_of_chunks
    #puts "repeat key plaintext: #{key}"

    # FIXME: add debug output options to these..
    repeat_key = Convert.ascii_to_bytes(key)
    #puts "repeat key in bytes: #{repeat_key}"

    p = text_bytes

    k = repeat_key

    #p.each_with_index do |byte, index|
      #puts "%4i - %4i^%4i = %s" % [ index, byte, k[index], (byte ^ k[index]).chr ]
    #end

    result = ""

    # FIXME: replace with repeat xor
    # FIXME: add debug output to xor
    p.each_with_index do |byte, index|
      result += "%s" % (byte ^ k[index]).chr
    end

    result
  end

  def self.aes_decrypt(text_plain, key, bits: 128, mode: :ECB, padding: 128)
    cipher = OpenSSL::Cipher::AES.new(bits, mode)

    cipher.decrypt
    cipher.key = key
    cipher.padding = padding

    cipher.update(text_plain) + cipher.final
  end


  def self.detect_ecb_from_text(text)
    likely_ecb_texts = []

    line_number = 1

    text.each_line do |line|

      cipher_text = Convert.bytes_to_ascii(Convert.hex_to_bytes(line))

      slices = cipher_text.split('').each_slice(16).map { |slice| slice }

      slice_counts = Hash.new(0)

      slices.each { |slice| slice_counts[slice] += 1 }

      # only keep each block if it repeats more than once
      slice_counts.keep_if { |k,v| v.to_i > 1 }

      unless slice_counts.empty?
        likely_ecb_texts.push({
          :line_number  => line_number,
          :cipher_text  => line,
          :slice_counts => slice_counts
        })
      end

      line_number += 1
    end

    likely_ecb_texts
  end

  # FIXME: rename to pad message?
  def self.pad_block(bytes, block_length)

    # if the message is smaller than block length then

    if bytes.length <= block_length

      padding_byte = block_length - bytes.length

      padding_byte = block_length if padding_byte == 0

    # if the message is longer than the block length then work out the remainer
    else
      padding_byte = block_length - (bytes.length % block_length)
    end

    (0...padding_byte).each { bytes.push padding_byte }

    bytes
  end

  # NOTE: set padding: 0 to use in non-ecb mode (raw)!
  def self.aes_encrypt(message, key, bits: 128, mode: :ECB, padding: 128)

    cipher = OpenSSL::Cipher::AES.new(bits, mode)

    #raise ArgumentError, "input must be '#{bits / 8}' bytes long for aes-#{bits}! message length: #{text_plain.length}, message: #{text_plain}"

    cipher.encrypt
    cipher.key = key
    cipher.padding = padding

    Convert.ascii_to_bytes(cipher.update(Convert.bytes_to_ascii(message)) + cipher.final)
  end

  # FIXME: this is potentially untrustworthy!
  # http://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/601px-CBC_encryption.svg.png
  def self.cbc_encrypt(message, block_size, iv, key)

    # iv            = block to merge with current block on next cbc iteration
    # merged_block  = resulting block after merge with iv
    # merged_blocks = combination of all resulting blocks

    merged_blocks = message.each_slice(block_size).map do |block|

      merged_block = Convert.xor(block, iv)

      iv = aes_encrypt(merged_block, key, padding: 0)

      iv
    end

    merged_blocks.flatten
  end

  # http://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/601px-CBC_decryption.svg.png
  def self.cbc_decrypt(message, block_size, iv, key)

    unmerged_blocks = message.each_slice(block_size).map do |block|

      unencrypted_block = aes_decrypt(Convert.bytes_to_ascii(block), key, padding: 0)

      unmerged_block = Convert.xor(Convert.ascii_to_bytes(unencrypted_block), iv)

      if $DEBUG
        puts "iv: #{iv}"
        puts "encrypted_block: #{block.inspect}"
        puts "unencrypted_block: #{unencrypted_block}"
        puts "unmerged_block: #{Convert.bytes_to_ascii(unmerged_block)}"
        puts
      end

      iv = block

      unmerged_block
    end

    # FIXME: refactor! this works but is full of nasty..

    # remove padding..

    # inspect last block
    last_block = unmerged_blocks[-1]

    # if last byte is in range of possible padding byte values...
    if last_block[-1].between?(0, block_size)

      # get last byte
      possible_padding_byte = last_block[-1]

      # look at the last bytes and see if they are all the same and the amount of them
      # matches their value..
      padded = last_block[-possible_padding_byte..-1].map do |byte|
        break unless byte == possible_padding_byte
      end

      if padded
        # we've found padding!
        (0...possible_padding_byte).each { last_block.delete_at(-1) }

        unmerged_blocks[-1] == last_block
      end
    end

    unmerged_blocks.flatten
  end

  def self.random_bytes(start: 0, length: 16)
    (start...start+length).map { random_byte }
  end

  self.singleton_class.send(:alias_method, :random_key, :random_bytes)

  def self.random_byte
    rand(33...126)
  end

  # encryption oracle
  def self.aes_encrypt_with_random_key_and_random_mode(message)
    # append random 5-10 bytes before and after plain text
    padded_message = pad_block([
      random_bytes(start: rand(1..5), length: 5),
      message,
      random_bytes(start: rand(1..5), length: 5),
    ].flatten, 16)

    random_key_ascii = Convert.bytes_to_ascii(random_key)

    #ap padded_message

    # encrypt ecb 50% of the time, cbc 50% of the time..
    if rand(2) == 1
      {
        message: aes_encrypt(padded_message, random_key_ascii),
        mode: :ecb,
        key: random_key_ascii
      }
    else

      iv = Convert.hex_to_bytes("0#{rand(2)}") * 16

      {
        message: cbc_encrypt(padded_message, 16, iv, random_key_ascii),
        mode: :cbc,
        key: random_key_ascii,
        iv: iv,
      }
    end
  end

  def self.detect_ecb(message)
    cipher_text = message

    slices = cipher_text.each_slice(16).map { |slice| slice }

    slice_counts = Hash.new(0)

    slices.each { |slice| slice_counts[slice] += 1 }

    # only keep each block if it repeats more than once
    slice_counts.keep_if { |k,v| v.to_i > 1 }

    return ({ :cipher_text  => message, :slice_counts => slice_counts }) unless slice_counts.empty?
  end

  # detect ecb with an offset.. if it's not ecb then it must be cbc
  def self.detect_aes_mode(message, length=10)
    (0...length).each do
      result = detect_ecb(message)

      return :ecb if result != nil

      message.shift
    end

    :cbc
  end

  # encryption oracle
  def self.aes_encrypt_with_random_key_and_random_mode(message)
    # append random 5-10 bytes before and after plain text
    padded_message = pad_block([
      random_bytes(start: rand(1..5), length: 5),
      message,
      random_bytes(start: rand(1..5), length: 5),
    ].flatten, 16)

    random_key_ascii = Convert.bytes_to_ascii(random_key)

    #ap padded_message

    # encrypt ecb 50% of the time, cbc 50% of the time..
    if rand(2) == 1
      {
        message: aes_encrypt(padded_message, random_key_ascii),
        mode: :ecb,
        key: random_key_ascii
      }
    else

      iv = Convert.hex_to_bytes("0#{rand(2)}") * 16

      {
        message: cbc_encrypt(padded_message, 16, iv, random_key_ascii),
        mode: :cbc,
        key: random_key_ascii,
        iv: iv,
      }
    end
  end
end
