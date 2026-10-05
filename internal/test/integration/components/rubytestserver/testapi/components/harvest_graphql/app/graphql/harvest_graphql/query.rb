module HarvestGraphql
  class Query < GraphQL::Schema::Object
    field :greeting, String, null: false do
      argument :name, String, required: true
    end

    def greeting(name:)
      "Hello, #{name}!"
    end
  end
end
