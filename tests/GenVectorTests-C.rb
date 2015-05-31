#!/usr/bin/env ruby

########################################################################
# This script is taken from RNCryptor/RNCryptorTests
# The script is modified to generate test programs for RNCryptor-C using the
# test vectors from RNCryptor. It uses only data format v3 vectors
# - muquit@muquit.com May-28-2015
########################################################################

require 'optparse'
ME=File.basename($0)
#require File.join(File.dirname(__FILE__), '../Spec/vectors', 'vectorparser')
require_relative 'vectorparser'

@test_files = ["v3/kdf", "v3/password", "v3/key", 
               "v2/kdf", "v2/password",
               "v1/kdf", "v1/password",
              ]

@options = {}
@funcs = []

# Returns the text for an NSDictionary assignment from a hash
def NSDictionaryForHash(hash)
#  "@{\n" + hash.collect { |key, value| %Q(    @"#{key}": @"#{value}") }.join(",\n") + "}"
  "(\n" + hash.collect { |key, value| %Q(    "#{value}") }.join(",\n")
end

# Output the file header to output stream
def outputHeader(output)
  t = Time.new
  code = File.read("./verify.c")
  output << <<-HEADER
/*
** WARNING: This file is auto generated. DO NOT MODIFY
** #{t} by #{ME}
*/
#{code}
HEADER
end

# Output the tests for a given filename to the output stream
# ignore v1 and v2
def outputTestsForFile(output, name)
  name_identifier = name.gsub('/', '_')
  return if name_identifier =~ /v1/
  return if name_identifier =~ /v2/
  x = "blah"
  VectorParser.new(@options[:vector_directory] + '/' + name).vectors.each do |vector|
  func = "test_#{name_identifier}_#{vector["title"].gsub(/[ ()-]+/, '_')}"
  if name_identifier != x
    x = name_identifier
  end
  @funcs << func
  output << <<-TEST_CASE

void #{func}(void)
{
  verify_#{name_identifier}#{NSDictionaryForHash(vector)});
}

TEST_CASE

  end
end

# Output the footer to the output stream
def outputFooter(output)
  output<< <<-MAIN
int main(int argc,char \*\*argv)
{
MAIN
    x="junk"
    @funcs.each do |func|
      if func =~ /^test_(v\d+_[a-z]+)_.+$/
        v = $1
        if v != x
          output << <<-TTT
    (void)fprintf(stderr,"Verify #{v}\\n");
TTT
          x = v
        end
      end
    output<< <<-FOOTER
    #{func}();
FOOTER
    end
    output<< <<-EEE
    return(0);
}
EEE
end

###################
### MAIN
###################
opt_parser = OptionParser.new do |opt|
  opt.banner = "Usage: GenVectorTest -o VectorTests.m <vector_directory>"
  opt.separator  ""
  opt.on("-o","--output PATH","path to output code") do |output_path|
    @options[:output_path] = output_path
  end
  opt.on("-3", "-3 PATH", "path to v3 directory") do |v3_directory|
    @options[:v3_directory] = v3_directory
  end
end

opt_parser.parse!

raise OptionParser::MissingArgument if @options[:output_path].nil?
raise OptionParser::MissingArgument if ARGV.length != 1

@options[:vector_directory] = ARGV[0]

File.open(@options[:output_path], "w") do |output|
  outputHeader(output)
  @test_files.each do |file|
    outputTestsForFile(output, file)
  end
  outputFooter(output)
end
