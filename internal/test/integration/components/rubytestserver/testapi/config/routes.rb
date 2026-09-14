Rails.application.routes.draw do
  resources :users

  draw :orders
  scope "/harvest/api" do
    draw "api/widgets"
  end

  get "/smoke", to: "users#smoke"
  get "/json_logger", to: "users#json_logger"
  get "/json_logger_write", to: "users#json_logger_write"
end
