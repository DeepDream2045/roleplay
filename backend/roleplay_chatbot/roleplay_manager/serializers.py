from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from .models import CustomUser, TokenRequest, ChatMessage

class RegisterSerializer(serializers.ModelSerializer):
    """ User registration serializer view"""

    class Meta:
        model = CustomUser
        fields = ('id','full_name', 'email', 'phone','stay_sign','profile_image','password')
        depth=1
        extra_kwargs = {
            "password": {"write_only": True}
        }

    full_name = serializers.CharField(label='Name', required=True)
    email = serializers.CharField(label='Email', required=True)
    password = serializers.CharField(label='Password', required=True)
    # confirm_password = serializers.CharField(label='Confirm Password',
    #                                          required=True)
    stay_sign = serializers.BooleanField(label='Stay signed in for a week ',
                                             required=True)

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
        fields = ('id', 'full_name', 'email','profile_image')


class ChatMessageSerializer(serializers.ModelSerializer):
    """Serializer for Chat Message """

    sender = CustomUserSerializer()
    receiver = CustomUserSerializer()
    class Meta:
        model = ChatMessage
        fields = ('id', 'sender', 'message', 'receiver', 'timestamp', 'is_edited')

    def create(self, validated_data):
        """creating Chat Message object"""
        profile_instance = ChatMessage.objects.create(**validated_data)
        return profile_instance


class MagicLoginSerializer(serializers.Serializer):
    """Magic Login serializer """
    email = serializers.CharField(label='email', required=True)

