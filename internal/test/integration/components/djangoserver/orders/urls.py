from django.http import JsonResponse
from django.urls import path


def order_detail(request, order_id):
    return JsonResponse({"order_id": order_id})


urlpatterns = [
    path("<int:order_id>/", order_detail),
]
