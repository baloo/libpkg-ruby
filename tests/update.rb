require 'pkg'

repos = Pkg::Repo.list()
puts repos.inspect
repos.each do |r|
  r.update()
end
puts repos.inspect

