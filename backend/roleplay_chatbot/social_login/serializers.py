from rest_framework import serializers
from roleplay_manager.models import CustomUser

class UserSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = CustomUser
        fields = ['id', 'full_name', 'username', 'email', 'profile_image']