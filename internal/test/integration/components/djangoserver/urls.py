from django.conf.urls.i18n import i18n_patterns
from django.contrib import admin
from django.http import HttpResponse
from django.urls import include, path, re_path

credit_patterns = [
    path("reports/", lambda request: HttpResponse("reports")),
]

urlpatterns = [
    path("smoke/", lambda request: HttpResponse("ok")),
    re_path(r"^articles/(?P<year>[0-9]{4})/$", lambda request, year: HttpResponse(year)),
    path("credit/", include(credit_patterns)),
    path("billing/", include((credit_patterns, "credit"), namespace="billing")),
    path("retail/", include(("checkout.urls", "checkout"), namespace="retail")),
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
