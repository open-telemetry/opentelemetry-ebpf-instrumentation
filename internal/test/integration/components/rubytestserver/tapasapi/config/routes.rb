Rails.application.routes.draw do
  get "/healthz", to: proc { [200, {}, ["ok"]] }
  get "/prepared-restaurants", to: "restaurants#prepared"

  resources :restaurants, only: [:index, :show] do
    resources :reviews, only: [:index, :create]
  end
end
