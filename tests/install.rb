require 'pkg'

Pkg::Pkg.init()
Pkg::EventHandler.install()

pkg = Pkg::Search.new(:remote)

job = pkg.search_install("zsh")

job.apply()

