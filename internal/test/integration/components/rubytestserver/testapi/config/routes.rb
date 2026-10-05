Rails.application.routes.draw do
  resources :users

  # Exercise the same engine at the root and under a prefix; Rails needs distinct mount names.
  mount HarvestGraphql::Engine, at: "/"
  mount HarvestGraphql::Engine, at: "/harvest/engine", as: "prefixed_graphql"

  draw :orders
  scope "/harvest/api" do
    draw "api/widgets"
  end

  get "/smoke", to: "users#smoke"
  get "/json_logger", to: "users#json_logger"
  get "/json_logger_write", to: "users#json_logger_write"
end
