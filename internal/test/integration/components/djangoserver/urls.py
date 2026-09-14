from django.conf.urls.i18n import i18n_patterns
from django.contrib import admin
from django.http import HttpResponse
from django.urls import include, path

urlpatterns = [
    path("smoke/", lambda request: HttpResponse("ok")),
    path("shop/", include("checkout.urls")),
    path("wholesale/", include("checkout.urls")),
    path("backoffice/", admin.site.urls),
]

urlpatterns += i18n_patterns(
    path("localized/", include("checkout.urls")),
)

urlpatterns += i18n_patterns(
    path("optional-language/", include("checkout.urls")),
    prefix_default_language=False,
)
