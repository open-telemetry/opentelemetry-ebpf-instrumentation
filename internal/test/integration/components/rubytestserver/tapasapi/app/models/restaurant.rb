class Restaurant < ApplicationRecord
  has_many :reviews, dependent: :destroy

  scope :search, ->(q) {
    return all if q.blank?

    where("name ILIKE :q OR neighborhood ILIKE :q OR food_type ILIKE :q", q: "%#{q}%")
  }
  scope :in_neighborhood, ->(n) { n.present? ? where("neighborhood ILIKE ?", n) : all }
  scope :of_food_type, ->(t) { t.present? ? where("food_type ILIKE ?", t) : all }

  def average_rating
    reviews.average(:rating)&.round(1)
  end
end
