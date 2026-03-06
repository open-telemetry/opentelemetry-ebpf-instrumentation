$stdout.sync = true

class UsersController < ApplicationController
  before_action :set_user, only: %i[ show update destroy ]

  # GET /smoke
  def smoke
    render plain: "OK"
  end

  # GET /json_logger — uses puts (writev syscall)
  def json_logger
    sleep 0.05
    message = "this is a json log from ruby"
    puts '{"message":"' + message + '","level":"INFO"}'
    render plain: message
  end

  # GET /json_logger_write — uses syswrite (write syscall)
  def json_logger_write
    sleep 0.05
    message = "this is a json log from ruby via write"
    STDOUT.syswrite('{"message":"' + message + '","level":"INFO"}' + "\n")
    render plain: message
  end

  # GET /users
  def index
    @users = User.all

    render json: @users
  end

  # GET /users/1
  def show
    render json: @user
  end

  # POST /users
  def create
    @user = User.new(user_params)

    if @user.save
      render json: @user, status: :created, location: @user
    else
      render json: @user.errors, status: :unprocessable_entity
    end
  end

  # PATCH/PUT /users/1
  def update
    if @user.update(user_params)
      render json: @user
    else
      render json: @user.errors, status: :unprocessable_entity
    end
  end

  # DELETE /users/1
  def destroy
    @user.destroy
  end

  private
    # Use callbacks to share common setup or constraints between actions.
    def set_user
      @user = User.find(params[:id])
    end

    # Only allow a list of trusted parameters through.
    def user_params
      params.require(:user).permit(:name, :email)
    end
end
