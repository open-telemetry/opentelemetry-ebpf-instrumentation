HarvestGraphql::Engine.routes.draw do
  post "/graphql", to: "queries#execute"
  post "/graphql/:tenant_id", to: "queries#execute"
end
