from django.urls import path
from . import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView
)

urlpatterns = [
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_refresh'),

    path('register/', views.Registraion.as_view(), name='registration'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('forget_password/', views.ForgetPassword.as_view(), name='forget_password'),
    path('reset_password/', views.ResetPassword.as_view(), name='reset_password'),
    path('change_profile_image/', views.ChangeProfilePictureView.as_view(), name='change_profile_image'),
    path('email_confirmation/', views.EmailConfirmation.as_view(), name='email_confirmation'),
]
