module HarvestGraphql
  class Engine < ::Rails::Engine
    isolate_namespace HarvestGraphql
    config.root = File.expand_path("../..", __dir__)
  end
end
