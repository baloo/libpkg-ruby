require 'pkg'

pkg = Pkg::Search.new(:remote)

puts pkg.search("ruby").inspect
