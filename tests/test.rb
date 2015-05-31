#!/usr/bin/env ruby

########################################################################
# test encryption/decryption
# muquit@muquit.com May-22-2015 
########################################################################
require 'minitest/autorun'
require 'digest'

class TestRnCryptorC < MiniTest::Unit::TestCase

  def self.test_order
    return :alpha
  end
  def setup
    $stdout.sync = true
    @dir = File.expand_path(File.dirname(__FILE__))
    @password = 'test'
    @image = "#{@dir}/image.enc"
    @encrkey_file = "#{@dir}/encrkey.bin"
    @hmackey_file = "#{@dir}/hmackey.bin"
    pid = Process.pid
    @outfile = "/tmp/image#{pid}.jpg"
    @outfile2 = "/tmp/image2#{pid}.enc"
    @md5 = Digest::MD5.file(@image)
    @encrypt_password_prog = "./rn_encrypt"
    @decrypt_password_prog = "./rn_decrypt"
    @encrypt_with_key_prog = "./rn_encrypt_with_key"
    @decrypt_with_key_prog = "./rn_decrypt_with_key"
    @imagedigest = "c1176f6378356829d94086df47448f1d"
    ENV["RNCPASS"] = @password
  end

  # decrypt with password
  def test_a
    print ".DECRYPT WITH PASSWORD: "
    cmd = ''
    cmd << @decrypt_password_prog
    cmd << ' '
    cmd << @image
    cmd << ' '
    cmd << @outfile
    cmd << ">/dev/null 2>&1"
    system(cmd)
    rc = $?.exitstatus
    assert_equal(0,rc,"Could not decrypt image")
    digest = Digest::MD5.file(@outfile)
    assert_equal(@imagedigest,digest.hexdigest,"Corrupt encryption")
    puts "PASSED"
  end

  # encrypt with key
  def test_b
    print "ENCRYPT WITH KEY: "
    cmd = ''
    cmd << @encrypt_with_key_prog
    cmd << ' '
    cmd << @encrkey_file
    cmd << ' '
    cmd << @hmackey_file
    cmd << ' '
    cmd << @outfile
    cmd << ' '
    cmd << @outfile2
    cmd << ">/dev/null 2>&1"
    system(cmd)
    rc = $?.exitstatus
    assert_equal(0,rc,"Could not encrypt image with encryption key")
    puts "PASSED"
  end

  # decrypt with key
  def test_c
    print "DECRYPT WITH KEY: "
    cmd = ''
    cmd << @decrypt_with_key_prog
    cmd << ' '
    cmd << @encrkey_file
    cmd << ' '
    cmd << @hmackey_file
    cmd << ' '
    cmd << ' '
    cmd << @outfile2
    cmd << ' '
    cmd << @outfile
    cmd << ">/dev/null 2>&1"
    system(cmd)
    rc = $?.exitstatus
    assert_equal(0,rc,"Could not decrypt image with encryption key")
    digest = Digest::MD5.file(@outfile)
    assert_equal(@imagedigest,digest.hexdigest,"Corrupt encryption")
    puts "PASSED"
  end

  # encrypt with password
  def test_e
    print "ENCRYPT WITH PASSWORD: "
    cmd = ''
    cmd << @encrypt_password_prog
    cmd << ' '
    cmd << @outfile
    cmd << ' '
    cmd << @outfile2
    cmd << ">/dev/null 2>&1"
    system(cmd)
    rc = $?.exitstatus
    assert_equal(0,rc,"Could not encrypt image with password")
    puts "PASSED"
  end

  # decrypt with password again
  def test_f
    print "DECRYPT WITH PASSWORD: "
    cmd = ''
    cmd << @decrypt_password_prog
    cmd << ' '
    cmd << @outfile2
    cmd << ' '
    cmd << @outfile
    cmd << ">/dev/null 2>&1"
    system(cmd)
    rc = $?.exitstatus
    assert_equal(0,rc,"Could not encrypt image with password")
    digest = Digest::MD5.file(@outfile)
    assert_equal(@imagedigest,digest.hexdigest,"Corrupt encryption")
    puts "PASSED"
  end

  def test_g
    print "DECRYPT TEXTFILE WITH PASSWORD: "
    cmd = ''
    cmd << @decrypt_password_prog
    cmd << ' '
    cmd << "#{@dir}/test.enc"
    cmd << ' '
    cmd << "-"
    cmd << ' '
    cmd << "2>/dev/null"
    text=`#{cmd}`.chomp
    assert_equal("this is a test",text)
    puts "PASSED"
  end

  def test_z
    system("/bin/rm -f #{@outfile}")
    system("/bin/rm -f #{@outfile2}")
  end

end
