from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from .models import *
from rest_framework.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
import json


class RegisterSerializer(serializers.ModelSerializer):
    """ User registration serializer view"""

    class Meta:
        model = CustomUser
        fields = ('id', 'full_name', 'username', 'email', 'phone',
                  'stay_sign', 'profile_image', 'password')
        depth = 1
        extra_kwargs = {
            "password": {"write_only": True}
        }

    full_name = serializers.CharField(label='Name', required=True)
    email = serializers.CharField(label='Email', required=True)
    password = serializers.CharField(label='Password', required=True)
    stay_sign = serializers.BooleanField(
        label='Stay signed in for a week', required=True)

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
            raise serializers.ValidationError(
                detail='Refresh token is required.')
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            raise serializers.ValidationError(
                detail='Token is expired or invalid.')


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
        fields = ('id', 'full_name', 'username', 'email', 'profile_image')


class ModelInfoSerializer(serializers.ModelSerializer):
    """Serializer for ModelInfo model to send Modals info"""

    class Meta:
        model = ModelInfo
        fields = '__all__'
        read_only_fields = ['user']

    def validate(self, attrs):
        # Check if the model_name is unique
        model_name = attrs.get('model_name', '')
        if ModelInfo.objects.filter(model_name=model_name).exists():
            raise serializers.ValidationError(
                {'model_name': 'Model name is already exist.'})

        return attrs

    def create(self, validated_data):
        """creating model info object"""

        validated_data['user'] = self.context['request'].user
        # Check if huggingFace_model_name is present
        huggingFace_model_name = validated_data.get('huggingFace_model_name')
        if not huggingFace_model_name:
            raise serializers.ValidationError({
                'huggingFace_model_name': [
                    'This field is required'
                ]
            })
        model_info_instance = ModelInfo.objects.create(**validated_data)
        return model_info_instance

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        user_representation = CustomUserSerializer(instance.user).data
        representation['user'] = user_representation
        return representation


class UserInfoSerializer(serializers.ModelSerializer):
    """Serializer for user information  """

    class Meta:
        model = CustomUser
        fields = ['id', 'full_name', 'username', 'profile_image']


class CharacterInfoSerializer(serializers.ModelSerializer):
    """Serializer for create characters  """

    user = UserInfoSerializer(many=False, read_only=True)
    tags = serializers.PrimaryKeyRelatedField(
        queryset=Tag.objects.all(), many=True, required=False)

    class Meta:
        model = CharacterInfo
        fields = '__all__'

    def validate(self, attrs):
        user = self.context["user"]
        attrs['user'] = user
        return attrs


class TagInfoSerializer(serializers.ModelSerializer):
    """Serializer for Tags  """

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
        extra_kwargs = {'chat': {'required': False}}


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
        fields = ('room_id', 'type', 'group_name',
                  'user', 'character', 'chatroom')


class CharacterTagInfoSerializer(serializers.ModelSerializer):
    """Serializer for get character tags information"""

    class Meta:
        model = Tag
        fields = ['id', 'tag_name']


class CharacterModelInfoSerializer(serializers.ModelSerializer):
    """Serializer for get character modal information"""

    class Meta:
        model = ModelInfo
        fields = ['id', 'model_name', 'short_bio',
                  'prompt_template', 'temperature', 'repetition_penalty', 'top_p', 'top_k']


class UserCreatedCharacterInfoSerializer(serializers.ModelSerializer):
    """Serializer for get character information"""
    model_id = CharacterModelInfoSerializer(many=False, read_only=True)
    user = UserInfoSerializer(many=False, read_only=True)
    tags = CharacterTagInfoSerializer(many=True, read_only=True)

    class Meta:
        model = CharacterInfo
        fields = '__all__'

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        # Fetch and include data for the related model with its ID
        model_id_data = CharacterModelInfoSerializer(instance.model_id).data
        user_data = UserInfoSerializer(instance.user).data
        tags_data = CharacterTagInfoSerializer(
            instance.tags.all(), many=True).data
        representation['model_id'] = model_id_data
        representation['user'] = user_data
        representation['tags'] = tags_data

        return representation


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
        fields = ['id', 'full_name', 'username', 'email',
                  'phone', 'profile_image', 'stay_sign']
        extra_kwargs = {'email': {'required': False},
                        'username': {'required': False}}


class PublicCharacterInfoSerializer(serializers.ModelSerializer):
    user = UserInfoSerializer(many=False, read_only=True)
    tags = CharacterTagInfoSerializer(many=True, read_only=True)

    class Meta:
        model = CharacterInfo
        fields = '__all__'


class EntryInfoSerializer(serializers.ModelSerializer):
    """ Serializer for Lorebook Entry Info """

    keys = serializers.ReadOnlyField(source='convert_keys_list')
    secondary_keys = serializers.ReadOnlyField(
        source='convert_secondary_keys_list')

    class Meta:
        model = LorebookEntries
        fields = ('name', 'keys', 'condition', 'secondary_keys', 'content',
                  'probability', 'order', 'is_enabled', 'is_exclude_recursion', 'lorebook')
        # extra_kwargs = {'user': {'required': False}}


class LorebookInfoSerializer(serializers.ModelSerializer):
    """ Serializer for Lorebook Info """

    user = UserInfoSerializer(many=False, read_only=True)
    entries = EntryInfoSerializer(many=True, read_only=True)

    class Meta:
        model = Lorebook
        fields = ('name', 'description', 'is_public',
                  'user', 'entries')
        extra_kwargs = {'user': {'required': False}}


class GuestUserCreateSerializer(serializers.ModelSerializer):
    """For guest user creation class serializer"""

    class Meta:
        model = CustomUser
        fields = ['id', 'is_guest', 'full_name', 'username', 'email']


class GuestRoomInfoChatSerializer(serializers.ModelSerializer):
    """Serializer for guest Room Info Chat Message """
    user = UserInfoSerializer(many=False, read_only=True)
    character = RoomCharacterInfoSerializer(many=False, read_only=True)

    class Meta:
        model = ChatRoom
        fields = ('room_id', 'type', 'group_name', 'user', 'character')


class LoraModelInfoSerializer(serializers.ModelSerializer):
    """Serializer for Lora modal Info"""

    class Meta:
        model = LoraModelInfo
        fields = '__all__'
        read_only_fields = ['user']

    def validate(self, attrs):
        # Check if the lora_model_name is unique
        lora_model_name = attrs.get('lora_model_name', '')
        if LoraModelInfo.objects.filter(lora_model_name=lora_model_name).exists():
            raise serializers.ValidationError(
                {'lora_model_name': 'This Lora Model name already exists.'})
        return attrs

    def create(self, validated_data):
        user = self.context['user']
        validated_data['user'] = user
        model_info_instance = LoraModelInfo.objects.create(**validated_data)
        return model_info_instance


class LoraModelInfoListSerializer(serializers.ModelSerializer):
    """Serializer for Lora modal Info"""

    class Meta:
        model = LoraModelInfo
        # fields = '__all__'
        exclude = ['tuned_model_path']


class ModelInfoListSerializer(serializers.ModelSerializer):
    """Serializer for Lora modal Info"""

    class Meta:
        model = ModelInfo
        # fields = '__all__'
        exclude = ['model_location']


class LoraTrainingStatusSerializer(serializers.ModelSerializer):
    """Serializer for Lora modal  status Info"""

    class Meta:
        model = LoraTrainingStatus
        fields = '__all__'
        # exclude = ['model_location']
