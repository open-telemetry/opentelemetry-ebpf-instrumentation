class RestaurantsController < ApplicationController
  def index
    restaurants = Restaurant.search(params[:q])
                             .in_neighborhood(params[:neighborhood])
                             .of_food_type(params[:food_type])
                             .order(:name)

    render json: restaurants.map { |r| restaurant_summary(r) }
  end

  def show
    restaurant = Restaurant.find(params[:id])
    render json: restaurant_detail(restaurant)
  rescue ActiveRecord::RecordNotFound
    render json: { error: "Restaurant not found" }, status: :not_found
  end

  private

  def restaurant_summary(restaurant)
    {
      id: restaurant.id,
      name: restaurant.name,
      neighborhood: restaurant.neighborhood,
      food_type: restaurant.food_type,
      price_range: restaurant.price_range,
      average_rating: restaurant.average_rating,
    }
  end

  def restaurant_detail(restaurant)
    restaurant_summary(restaurant).merge(
      description: restaurant.description,
      address: restaurant.address,
      reviews: restaurant.reviews.order(created_at: :desc).map do |review|
        {
          id: review.id,
          author: review.author,
          rating: review.rating,
          comment: review.comment,
          created_at: review.created_at,
        }
      end
    )
  end
end
