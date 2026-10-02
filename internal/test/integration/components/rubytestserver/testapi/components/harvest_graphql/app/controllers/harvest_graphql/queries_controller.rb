module HarvestGraphql
  class QueriesController < ActionController::API
    def execute
      result = Schema.execute(
        params.require(:query),
        variables: params[:variables]&.to_unsafe_h || {},
        operation_name: params[:operationName]
      )
      render json: result
    end
  end
end
