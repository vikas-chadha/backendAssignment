from django.urls import path
from .views import *

app_name = 'api'

urlpatterns = [
    path('auth/login', LoginView.as_view(), name='login'),
    path('auth/sign-up/', SignupView.as_view(), name='auth-sign-up'),
    path('create-post/', CreatePostView.as_view(), name="create-post"),


]
