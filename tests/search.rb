require 'pkg'
require 'riot'

context "Pkg search for package" do
  pkg = Pkg::Search.new(:remote)

  puts pkg.search("ruby").class

  asserts(pkg.search("ruby")).kind_of(Array.new)
end
