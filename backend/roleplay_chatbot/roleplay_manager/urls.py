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
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),

    path('register/', views.Registraion.as_view(), name='registration'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('forget_password/', views.ForgetPassword.as_view(), name='forget_password'),
    path('reset_password/', views.ResetPassword.as_view(), name='reset_password'),

    path('change_profile_image/', views.ChangeProfilePictureView.as_view(), name='change_profile_image'),
    path('email_confirmation/', views.EmailConfirmation.as_view(), name='email_confirmation'),

    path('login_request/', views.MagicLoginRequestView.as_view(), name='magic_login_request'),
    path('login_verify/', views.MagicLoginVerifyView.as_view(), name='magic_login_verify'),

    path('model_info/', views.ModelInfoAPIView.as_view(), name='model_info'),

    path('tag_info/', views.TagInfoView.as_view(), name='tag_info'),
    path('public_tag_info/', views.TagListInfoView.as_view(), name='public_tag_info'),

    path('character_info/', views.CharacterInfoView.as_view(), name='character_info'),
    path('character_info_by_id/', views.CharacterInfoByIDView.as_view(), name='character_info'),
    path('public_character_info/', views.PublicCharacterInfoView.as_view(), name='public_character_info'),

    path('room_info/', views.RoomInfoChatView.as_view(), name='room_info'),
    path('chat_message/', views.ChatMessageView.as_view(), name='chat_message'),
    path('feedback/', views.FeedbackView.as_view(), name='feedback'),
    path('user_profile/', views.UserProfileView.as_view(), name='user_profile'),
]
