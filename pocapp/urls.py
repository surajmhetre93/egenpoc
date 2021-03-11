from django.urls import path
from .views import APIConfig


urlpatterns = [
    path('APIConfig/', APIConfig.as_view()),
]