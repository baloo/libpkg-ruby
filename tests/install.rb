require 'pkg'
require 'riot'

Pkg::Pkg.init()
Pkg::EventHandler.install()

pkg = Pkg::Search.new(:remote)

job = pkg.search_install(["zsh", "vim"])
#job = pkg.search_install([])

job.apply()

