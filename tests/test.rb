# frozen_string_literal: true
########################################################################
# test encryption/decryption
# Install the gem: gem install minitest
# muquit@muquit.com May-22-2015  -first cut
# Update:
#   - now the class is Minitest not MiniTest
#   - add i_suck_and_my_tests_are_order_dependent! to run the tests
#     in order
# (Mar-06-2026)
########################################################################
require 'minitest/autorun'
require 'digest'
require 'tmpdir'
require 'fileutils'

class TestRnCryptorC < Minitest::Test
  i_suck_and_my_tests_are_order_dependent!
  def self.test_order
    return :alpha
  end

  TMPDIR   = Dir.mktmpdir("rncryptorc_test")
  OUTFILE  = File.join(TMPDIR, "image.jpg")
  OUTFILE2 = File.join(TMPDIR, "image.enc")

  def setup
    $stdout.sync = true
    @dir = File.expand_path(File.dirname(__FILE__))
    @password = 'test'
    @image = "#{@dir}/image.enc"
    @encrkey_file = "#{@dir}/encrkey.bin"
    @hmackey_file = "#{@dir}/hmackey.bin"
    @outfile  = OUTFILE
    @outfile2 = OUTFILE2
    @encrypt_password_prog = "./rn_encrypt"
    @decrypt_password_prog = "./rn_decrypt"
    @encrypt_with_key_prog = "./rn_encrypt_with_key"
    @decrypt_with_key_prog = "./rn_decrypt_with_key"
    @imagedigest = "c1176f6378356829d94086df47448f1d"
    ENV["RNCPASS"] = @password
  end

  def test_a
    print "DECRYPT WITH PASSWORD: "
    cmd = +''
    cmd << @decrypt_password_prog
    cmd << ' ' << @image
    cmd << ' ' << @outfile
    cmd << " >/dev/null 2>&1"
    system(cmd)
    assert_equal(0, $?.exitstatus, "Could not decrypt image")
    assert_equal(@imagedigest, Digest::MD5.file(@outfile).hexdigest, "Corrupt encryption")
    puts "PASSED"
  end

  def test_b
    print "ENCRYPT WITH KEY: "
    cmd = +''
    cmd << @encrypt_with_key_prog
    cmd << ' ' << @encrkey_file
    cmd << ' ' << @hmackey_file
    cmd << ' ' << @outfile
    cmd << ' ' << @outfile2
    cmd << " >/dev/null 2>&1"
    system(cmd)
    assert_equal(0, $?.exitstatus, "Could not encrypt image with encryption key")
    puts "PASSED"
  end

  def test_c
    print "DECRYPT WITH KEY: "
    cmd = +''
    cmd << @decrypt_with_key_prog
    cmd << ' ' << @encrkey_file
    cmd << ' ' << @hmackey_file
    cmd << ' ' << @outfile2
    cmd << ' ' << @outfile
    cmd << " >/dev/null 2>&1"
    system(cmd)
    assert_equal(0, $?.exitstatus, "Could not decrypt image with encryption key")
    assert_equal(@imagedigest, Digest::MD5.file(@outfile).hexdigest, "Corrupt encryption")
    puts "PASSED"
  end

  def test_e
    print "ENCRYPT WITH PASSWORD: "
    cmd = +''
    cmd << @encrypt_password_prog
    cmd << ' ' << @outfile
    cmd << ' ' << @outfile2
    cmd << " >/dev/null 2>&1"
    system(cmd)
    assert_equal(0, $?.exitstatus, "Could not encrypt image with password")
    puts "PASSED"
  end

  def test_f
    print "DECRYPT WITH PASSWORD AGAIN: "
    cmd = +''
    cmd << @decrypt_password_prog
    cmd << ' ' << @outfile2
    cmd << ' ' << @outfile
    cmd << " >/dev/null 2>&1"
    system(cmd)
    assert_equal(0, $?.exitstatus, "Could not decrypt image with password")
    assert_equal(@imagedigest, Digest::MD5.file(@outfile).hexdigest, "Corrupt encryption")
    puts "PASSED"
  end

  def test_g
    print "DECRYPT TEXTFILE WITH PASSWORD: "
    cmd = +''
    cmd << @decrypt_password_prog
    cmd << ' ' << "#{@dir}/test.enc"
    cmd << ' ' << "-"
    cmd << " 2>/dev/null"
    text = `#{cmd}`.chomp
    assert_equal("this is a test", text)
    puts "PASSED"
  end

  def test_z
    FileUtils.rm_rf(TMPDIR)
  end
end
