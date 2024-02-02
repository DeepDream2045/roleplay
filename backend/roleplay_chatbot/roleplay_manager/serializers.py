from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from .models import *
import json

class RegisterSerializer(serializers.ModelSerializer):
    """ User registration serializer view"""

    class Meta:
        model = CustomUser
        fields = ('id','full_name', 'username', 'email', 'phone','stay_sign','profile_image','password')
        depth=1
        extra_kwargs = {
            "password": {"write_only": True}
        }

    full_name = serializers.CharField(label='Name', required=True)
    email = serializers.CharField(label='Email', required=True)
    password = serializers.CharField(label='Password', required=True)
    stay_sign = serializers.BooleanField(label='Stay signed in for a week',required=True)

    def validate(self, data):
        """validating request data"""
        email = data.get('email', None)
        password = data.get('password', None)
        confirm_password = data.get('confirm_password', None)
        # if password != confirm_password:
        #     return serializers.ValidationError("Passwords do not match")
        # data.pop('confirm_password', None)
        return data

    def create(self, validated_data):
        """creating user object"""

        validated_data['email'] = validated_data['email'].lower()
        validated_data['password'] = make_password(validated_data['password'])
        validated_data['is_active'] = True
        profile_instance = CustomUser.objects.create(**validated_data)

        return profile_instance

        
class LoginSerializer(serializers.Serializer):
    """Login serializer """
    email = serializers.CharField(label='email', required=True)
    password = serializers.CharField(label='Password', required=True)


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField(required=False)

    default_error_message = {
        'bad_token': ('Token is expired or invalid')
    }

    def validate(self, attrs):
        if not attrs.get('refresh'):
            raise serializers.ValidationError(detail='Refresh token is required.')
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            raise serializers.ValidationError(detail='Token is expired or invalid.')


class MagicLoginSerializer(serializers.Serializer):
    """Magic Login serializer """
    token = serializers.CharField(label='token', required=True)


class ForgotPasswordSerializer(serializers.ModelSerializer):
    """Forgot password serializer"""

    class Meta:
        model = TokenRequest
        fields = ['user', 'token']
        
    def validate(self, data):
        """Validating email """
        email = data.get('email', None)
        if email:
            if not CustomUser.objects.filter(email=email):
                raise serializers.ValidationError(
                    """Oops, this email does not exist on our records.
                        Please try again or Sign Up.""")
        return data


class ResetPasswordSerializer(serializers.Serializer):

    email = serializers.CharField(required=False)
    new_password = serializers.CharField(required=False)
    confirm_password = serializers.CharField(required=False)
    
    def validate(self, data):
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        if new_password != confirm_password:
            return serializers.ValidationError("Passwords do not match")
        data.pop('confirm_password', None)
        return data


class CustomUserSerializer(serializers.ModelSerializer):
    """Serializer for CustomUser model to send user info"""
    class Meta:
        model = CustomUser
        fields = ('id', 'full_name', 'username', 'email','profile_image')


class ModelInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = ModelInfo
        fields = '__all__'
        # extra_kwargs = {'user': {'required': False}} 

    def validate(self, attrs):
        attrs['user'] = self.context["user"]
        return super().validate(attrs)

    def create(self, validated_data):
        """creating model info object"""
        
        model_info_instance = ModelInfo.objects.create(**validated_data)
        return model_info_instance


class UserInfoSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = CustomUser
        fields = ['id', 'full_name', 'username', 'profile_image']


class CharacterInfoSerializer(serializers.ModelSerializer):
    user = UserInfoSerializer(many=False, read_only=True)
    tags = serializers.PrimaryKeyRelatedField(queryset=Tag.objects.all(), many=True, required=False)

    class Meta:
        model = CharacterInfo
        fields = '__all__'
        # extra_kwargs = {'tags': {'required': False}}

    def validate(self, attrs):
        attrs['user'] = self.context["user"]
        return attrs


class TagInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = '__all__'
        extra_kwargs = {'user': {'required': False}}

    def validate(self, attrs):
        attrs['user'] = self.context["user"]
        return super().validate(attrs)

    def create(self, validated_data):
        """creating character info object"""
        
        taginfo_instance = Tag.objects.create(**validated_data)
        return taginfo_instance


class CallLLMSerializer(serializers.Serializer):
    """Magic Login serializer """
    token = serializers.CharField(label='token', required=True)
    user = serializers.CharField(label='user', required=True)
    character_id = serializers.CharField(label='character_id', required=True)
    message = serializers.CharField(label='message', required=True)


class ChatMessageSerializer(serializers.ModelSerializer):
    """Serializer for Chat Message """
    
    class Meta:
        model = ChatMessage
        fields = '__all__'


class RoomCharacterInfoSerializer(serializers.ModelSerializer):

    class Meta:
        model = CharacterInfo
        fields = '__all__'


class RoomInfoChatSerializer(serializers.ModelSerializer):
    """Serializer for Room Info Chat Message """
    chatroom = ChatMessageSerializer(many=True, read_only=True)
    user = UserInfoSerializer(many=False, read_only=True)
    character = RoomCharacterInfoSerializer(many=False, read_only=True)

    class Meta:
        model = ChatRoom
        fields = ('room_id', 'type', 'group_name', 'user', 'character','chatroom')


class CharacterModelInfoSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = ModelInfo
        fields = [
            'id','model_name','short_bio','model_location',
            'prompt_template','temperature','repetition_penalty',
            'top_p','top_k'
        ]


class CharacterTagInfoSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = Tag
        fields = ['id', 'tag_name']


class UserCreatedCharacterInfoSerializer(serializers.ModelSerializer):
    model_id = CharacterModelInfoSerializer(many=False, read_only=True)
    user = UserInfoSerializer(many=False, read_only=True)
    tags = CharacterTagInfoSerializer(many=True, read_only=True)
    
    class Meta:
        model = CharacterInfo
        fields = '__all__'


class FeedbackSerializer(serializers.ModelSerializer):
    user = UserInfoSerializer(many=False, read_only=True)
    
    class Meta:
        model = Feedback
        fields = '__all__'
    
    def validate(self, attrs):
        attrs['user'] = self.context["user"]
        return super().validate(attrs)

    def create(self, validated_data):
        """creating character info object"""
        
        feedback_instance = Feedback.objects.create(**validated_data)
        return feedback_instance


class UserProfileInfoSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = CustomUser
        fields = ['id', 'full_name', 'email', 'phone', 'profile_image', 'stay_sign']
        extra_kwargs = {'email': {'required': False}}


class PublicCharacterInfoSerializer(serializers.ModelSerializer):
    user = UserInfoSerializer(many=False, read_only=True)
    character_tag = CharacterTagInfoSerializer(many=False, read_only=True)

    class Meta:
        model = CharacterInfo
        fields = '__all__'

