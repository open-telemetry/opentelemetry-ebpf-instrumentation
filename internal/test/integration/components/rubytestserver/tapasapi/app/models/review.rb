class Review < ApplicationRecord
  belongs_to :restaurant

  validates :author, presence: true
  validates :rating, presence: true, inclusion: { in: 1..5 }
end
