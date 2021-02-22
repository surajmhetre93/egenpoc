from django.urls import path, include
from pocapp import views

urlpatterns = [
    path('', views.home, name = "home"),
]