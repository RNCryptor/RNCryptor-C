#!/usr/bin/env ruby
#
# muquit@muquit.com xdaet 
require 'ruby_rncryptor'

begin
  ME = File.basename($0)
  password = ENV['XPASS']
  if !password
    puts "ERROR: set password in env variable XPASS"
    exit 1
  end
  if ARGV.length != 1
    puts "Usage: #{ME} <file.enc>"
    exit 1
  end
  encrypted_file = ARGV[0]
  encrypted_data = IO.binread(encrypted_file)
  decrypted_data = RubyRNCryptor.decrypt(encrypted_data,password)
  File.binwrite("image.jpg",decrypted_data)
rescue => e
  puts "ERROR: #{e}"
end
