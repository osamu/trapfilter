#!/usr/bin/ruby

class TrapFilter
  attr_reader :varbind

  def initialize(*option)
    @varbind = {}
    @options = option.shift || {:policy => "accept" }
    @rules = []
  end

  def import(reader)
    buffer = []
    while line = reader.gets
      break if line =~ /^$/
      buffer.push line.chomp
    end

    @varbind['HOST']= buffer.shift.strip
    if buffer.shift =~ /(\w+):\s+\[([\d\.]+)\]/
      @varbind['PROTOCOL'] = $1.strip
      @varbind['IP'] = $2.strip 
    end
    buffer.each do |var|
      key,value = var.split(/\s+/,2)
      @varbind[key] = value
    end
  end

  def add_rule(*rule)
    @rules = @rules.push(rule[0])
  end

  def filter_rule(rule)

    result = rule.map do |key,value|
      if @varbind[key]
        @varbind[key].include?(value)
      else
        false 
      end
    end
    result.inject(true) { |result,item| result and item }
  end

  def filter
    result = @rules.map { |rule| filter_rule(rule) }

    if @options[:policy] =~ /accept/
      return result.inject(false) { |result,item| result or item }
    else
      return !result.inject(false) { |result,item| result or item }
    end
  end

  def export(writer)
    writer.puts "#{@hostname}"
    writer.puts "#{@ip}"
    @varbind.each do |key,value|
      writer.puts "#{key} #{value}"
    end
  end
end

