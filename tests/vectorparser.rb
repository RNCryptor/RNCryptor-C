class VectorParser
  def initialize(path)
    @path = path
  end

  def vectors
    mapBlocksToVectors getBlocksFromLines getUncommentedLinesFromPath @path
  end

  private

  def getUncommentedLinesFromPath(path)
    File.readlines(path).select{ |line| line !~ /^#/ }.map { |line| line.sub(/^\s#.*/, "").chomp }
  end

  def getBlocksFromLines(lines)
    blocks = []
    block = []
    lines.each do |line|
      if line.length == 0
        if block.length > 0
          blocks << block
          block = []
        end
        next
      end

      block << line
    end

    if block.length > 0
      blocks << block
    end

    return blocks

    # lines.chunk { |l| (l =~ /^\s*$/) == nil }
    # .map { |not_blank, a| a if not_blank }
    # .compact
  end

  def mapBlocksToVectors(blocks)
    blocks.map { |block|
      Hash[*
        block.map { |l| l.split(/\s*:\s*/, 2) }.flatten
      ]
    }
  end
end