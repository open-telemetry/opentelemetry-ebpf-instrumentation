Rails.application.routes.draw do
  get "/healthz", to: proc { [200, {}, ["ok"]] }

  resources :restaurants, only: [:index, :show] do
    resources :reviews, only: [:index, :create]
  end
end
