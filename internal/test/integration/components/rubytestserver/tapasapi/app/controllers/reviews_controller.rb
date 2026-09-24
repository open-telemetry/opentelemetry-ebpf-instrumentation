class ReviewsController < ApplicationController
  before_action :set_restaurant

  def index
    render json: @restaurant.reviews.order(created_at: :desc)
  end

  def create
    review = @restaurant.reviews.new(review_params)

    if review.save
      render json: review, status: :created
    else
      render json: { errors: review.errors.full_messages }, status: :unprocessable_entity
    end
  end

  private

  def set_restaurant
    @restaurant = Restaurant.find(params[:restaurant_id])
  rescue ActiveRecord::RecordNotFound
    render json: { error: "Restaurant not found" }, status: :not_found
  end

  def review_params
    params.require(:review).permit(:author, :rating, :comment)
  end
end
