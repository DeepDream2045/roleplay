from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string
from rest_framework import generics
from rest_framework.views import APIView
from django.contrib import auth
from rest_framework.response import Response
from .serializers import *
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from roleplay_manager.permission import IsValidUser
from rest_framework_simplejwt.tokens import RefreshToken
from .models import *
from bot.pipeline import *
import uuid
import logging
from datetime import datetime
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from .utility import send_email, create_img_url
import json
from django.db.models import Q
from django.http import Http404
from roleplay_manager.task import fetch_lora_modal_data
from lora_finetune.run_adapter import RunLoraAdapter
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import configparser
import random
from eth_account.messages import encode_defunct
from web3.auto import w3


logger = logging.getLogger(__name__)
sys_random = random.SystemRandom()


def get_random_string(k=35):
    letters = "abcdefghiklmnopqrstuvwwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    return ''.join(sys_random.choices(letters, k=k))


def missing_field_error(field_name):
    """ function for showing error for required fields """
    return Response({'error': {
        field_name: [
            f'This field is required.'
        ]
    }}, status=status.HTTP_400_BAD_REQUEST)


class Registration(APIView):
    """Registration class view"""

    def post(self, request):
        """Create user view """

        password = request.data.get('password')
        confirm_password = request.data.get('confirm_password')
        if password != confirm_password:
            return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
        request.data.pop('confirm_password', None)

        serializer = RegisterSerializer(data=request.data)
        try:
            if serializer.is_valid():
                email = request.data['email']
                if CustomUser.objects.filter(email=email.lower()):
                    return Response({'error': "Email already used"})
                user = serializer.save()
                self.send_email_verification(serializer, user)
                refresh = RefreshToken.for_user(user)
                return Response({"message": 'success', 'data': serializer.data, 'refresh': str(refresh), 'access': str(refresh.access_token)}, status=status.HTTP_200_OK)

            return Response({"error": "Field error", "data": serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

        except Exception:
            logger.info(
                f"{datetime.now()} :: Registration post error :: {error}")
            return Response({"error": "Field error data not valid", "data": serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    def send_email_verification(self, serializer, user):
        if not user.email_confirmation:
            expiration_time = timezone.now() + timezone.timedelta(minutes=30)
            title = 'Email confirmation mail'
            email = user.email
            token = str(uuid.uuid4())
            encoded_email = email.encode('utf_16', 'strict').hex()
            token_create = TokenRequest.objects.create(
                user=user, token=token, expiration_time=expiration_time)
            urls = f"{settings.DASHBOARD_BASE_ROUTE}/email_confirmation/{token}/{encoded_email}/"
            if token_create:
                body_html = render_to_string(
                    'email_confirmation.html',
                    {'name': user.full_name, 'token': token,
                        'email': email.encode('utf_16', 'strict'), 'url': urls}
                )
                body_html += ''
                result = send_email(title, body_html, [email])
                if result:
                    return Response({'message': 'We have sent you a link on email please verify', 'user': serializer.data, }, status=status.HTTP_200_OK,)
            return Response({'error': 'Error while sending  email for email confirmation', 'user': serializer.data, }, status=status.HTTP_200_OK,)
        return Response({'message': 'Email already verified!', 'user': serializer.data, }, status=status.HTTP_200_OK)


class LoginView(APIView):
    """ Login view"""

    def post(self, request):
        """Login view """

        serializer = LoginSerializer(data=request.data)
        try:
            if serializer.is_valid():
                email = serializer.validated_data['email']
                password = serializer.validated_data['password']
                user = auth.authenticate(
                    request, email=email.lower(), password=password)
                if user is None:
                    return Response({'error': "Invalid credentials."})
                if user.is_active:
                    profile_image = ''
                    try:
                        if user.profile_image.url:
                            profile_image = create_img_url(
                                request, user.profile_image.url)
                    except ValueError:
                        profile_image = create_img_url(
                            request, user.profile_image)
                    refresh = RefreshToken.for_user(user)
                    response_data = {}
                    response_data['id'] = user.id
                    response_data['full_name'] = user.full_name
                    response_data['email'] = user.email
                    response_data['profile_image'] = profile_image
                    response_data['stay_sign'] = user.stay_sign
                    # response_data['refresh'] = str(refresh)
                    # response_data['access'] = str(refresh.access_token)
                    return Response({'message': 'success', 'data': response_data,
                                     'refresh': str(refresh), 'access': str(refresh.access_token)}, status=status.HTTP_200_OK, )
                return Response({'error': 'user not active', 'data': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as error:
            logger.info(f"{datetime.now()} :: LoginView post error :: {error}")
            return Response({"error": "Invalid Email or password"}, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = (IsAuthenticated, IsValidUser)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(status=status.HTTP_200_OK)
        return Response({'errors': serializer.errors}, status=status.HTTP_200_OK)


class ForgetPassword(APIView):
    """Forgot password class view"""

    def get(self, request, *args, **kwargs):
        """Get view """
        serializer = ForgotPasswordSerializer()
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        """post view"""
        expiration_time = timezone.now() + timezone.timedelta(minutes=5)
        try:
            user = CustomUser.objects.filter(
                email=request.data['email']).first()
            if user is not None:
                title = 'Forget Password'
                email = user.email
                token = str(uuid.uuid4())
                token_create = TokenRequest.objects.create(
                    user=user, token=token, expiration_time=expiration_time)
                urls = f"{settings.DASHBOARD_BASE_ROUTE}/reset_password/{token}/"
                if token_create:
                    body_html = render_to_string(
                        'forgot_password.html',
                        {'name': user.full_name, 'token': token, 'url': urls}
                    )
                    body_html += ''
                    result = send_email(title, body_html, [email])
                    return Response({'message': 'success'}, status=status.HTTP_200_OK,)

            return Response({'error': 'Email does not exists!'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            logger.info(
                f"{datetime.now()} :: ForgetPassword post error :: {error}")
            msg = "Error while sending  email for forgot password"
            return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)


class ResetPassword(APIView):
    """Reset password class view"""

    def get(self, request, *args, **kwargs):

        password_reset = TokenRequest.objects.get(token=request.GET['token'])
        if password_reset.expiration_time < timezone.now():
            return Response({'error': 'password_reset_expired'})
        else:
            return Response({"message": 'success'})

    def post(self, request, *args, **kwargs):
        """ reset password post view"""

        password_reset = TokenRequest.objects.get(token=request.data['token'])
        serializer = ResetPasswordSerializer(data=request.data)
        try:
            if password_reset.expiration_time < timezone.now():
                return Response({'error': 'password_reset_expired'})
            if serializer.is_valid():
                email = serializer.data.get('email')
                new_password = serializer.data.get('new_password')
                if email:
                    user = CustomUser.objects.filter(email=email).first()
                    if user is None:
                        return Response({'error': 'Email does not exists'})
                    user.password = make_password(new_password)
                    user.save()
                    return Response({'message': 'Password successfully updated'}, status=status.HTTP_200_OK,)
                return Response({'error': 'user does not exists'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            logger.info(
                f"{datetime.now()} :: ResetPassword post error :: {error}")
            return Response({'error': 'something went wrong'}, status=status.HTTP_400_BAD_REQUEST)


class ChangeProfilePictureView(APIView):
    """Change profile image view"""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            user_obj = CustomUser.objects.get(email=request.user)
            if user_obj:
                user_obj.profile_image = request.data['profile_image']
                user_obj.save()
                profile_image = ''
                try:
                    if user_obj.profile_image.url:
                        profile_image = create_img_url(
                            request, user_obj.profile_image.url)
                        return Response({"message": "Profile changed successfully!", 'profile_image': profile_image})
                except ValueError:
                    profile_image = create_img_url(
                        request, user_obj.profile_image)
                    return Response({"message": "Profile changed successfully!", 'profile_image': profile_image})
            return Response({"error": "User  does not exists!"})

        except CustomUser.DoesNotExist:
            return Response({"error": "User  does not exists!"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            logger.info(
                f"{datetime.now()} :: ChangeProfilePictureView post error :: {error}")
            return Response({"error": "User  does not exists!", 'err': error.__str__()}, status=status.HTTP_400_BAD_REQUEST)


class EmailConfirmation(APIView):
    """For email verification"""

    def post(self, request):
        """Email verification view"""

        try:
            email_confirm = TokenRequest.objects.get(
                token=request.data['token'])
            if email_confirm.expiration_time < timezone.now():
                return Response({'error': 'email_confirmation_link_expired'})
            email_bytes = bytes.fromhex(request.data['email'])
            decoded_email = email_bytes.decode('utf-16', 'strict')
            user = CustomUser.objects.get(email=decoded_email)
            if not user.email_confirmation:
                user.email_confirmation = True
                user.save()
                return Response({'message': 'Email is verified'}, status=status.HTTP_200_OK)
            return Response({'error': "Email already verified!"}, status=status.HTTP_400_BAD_REQUEST)

        except TokenRequest.DoesNotExist:
            return Response({'error': 'token does not exists!'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: EmailConfirmation post error :: {e}")
            return Response({'error': "Email does not exists!", 'error_msg': e.__repr__()}, status=status.HTTP_400_BAD_REQUEST)


class MagicLoginRequestView(APIView):
    """For Magic login request class view"""

    def post(self, request):
        """Implement logic to send the magic login link to the user's email
        This could involve generating a unique token and sending it in an email"""

        expiration_time = timezone.now() + timezone.timedelta(minutes=10)
        try:
            user = CustomUser.objects.filter(
                email=request.data['email']).first()
            if not user:
                email = request.data['email'].lower()
                user = CustomUser.objects.create(email=email)

            if user is not None:
                title = 'Sign into Roleplay'
                email = user.email
                token = str(uuid.uuid4())
                token_create = TokenRequest.objects.create(
                    user=user, token=token, expiration_time=expiration_time)
                urls = f"{settings.DASHBOARD_BASE_ROUTE}/login_verify/{token}/"
                if token_create:
                    body_html = render_to_string(
                        'login_mail.html', {'url': urls}
                    )
                    body_html += ''
                    result = send_email(title, body_html, [email])
                    return Response({'message': 'success'}, status=status.HTTP_200_OK,)
        except Exception as error:
            logger.info(
                f"{datetime.now()} :: MagicLoginRequestView post error :: {error}")
            msg = "Error while sending email for Login"
            return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)


class MagicLoginVerifyView(APIView):
    """Magic login verification class view"""

    def post(self, request, *args, **kwargs):
        """ Magic login verification post view"""

        token = TokenRequest.objects.get(token=request.data['token'])
        serializer = MagicLoginSerializer(data=request.data)

        try:
            if token.expiration_time < timezone.now():
                return Response({'error': 'token expired'}, status=status.HTTP_400_BAD_REQUEST)
            if serializer.is_valid():
                user = CustomUser.objects.filter(id=token.user.id).first()
                if user is None:
                    return Response({'error': 'token expired'}, status=status.HTTP_400_BAD_REQUEST)
                if not user.email_confirmation:
                    user.email_confirmation = True
                    user.is_active = True
                    user.provider = 'magic link'
                user.save()
                profile_image = ''
                try:
                    if user.profile_image.url:
                        profile_image = create_img_url(
                            request, user.profile_image.url)
                except ValueError:
                    profile_image = create_img_url(request, user.profile_image)
                refresh = RefreshToken.for_user(user)
                response_data = {}
                response_data['id'] = user.id
                response_data['full_name'] = user.full_name
                response_data['username'] = user.username
                response_data['email'] = user.email
                response_data['profile_image'] = profile_image
                response_data['stay_sign'] = user.stay_sign
                return Response({'message': 'success', 'data': response_data,
                                 'refresh': str(refresh), 'access': str(refresh.access_token)}, status=status.HTTP_200_OK, )
            return Response({'error': 'Email required'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            logger.info(
                f"{datetime.now()} :: MagicLoginVerifyView post error :: {error}")
            return Response({'error': 'something went wrong'}, status=status.HTTP_400_BAD_REQUEST)


class ModelInfoAPIView(generics.ListCreateAPIView, generics.RetrieveUpdateDestroyAPIView):

    permission_classes = [IsAuthenticated, IsValidUser]
    serializer_class = ModelInfoSerializer

    def get_serializer_context(self):
        """
        Extra context provided to the serializer class.
        """
        context = super().get_serializer_context()
        context.update({
            "user": self.request.user
        })
        return context

    def list(self, request, *args, **kwargs):
        """ 
        Fetch Model information
        """

        try:
            # Filter queryset based on user and is_public
            queryset = ModelInfo.objects.filter(
                Q(user=request.user) | Q(is_public=True))
            if not queryset.exists():
                return Response({'message': 'No modal found'})
            serializer = ModelInfoListSerializer(queryset, many=True)
            return Response(serializer.data)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: ModelInfoAPIView list error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def update(self, request, *args, **kwargs):
        """ 
        Update Model information including child model values.
        Request body: Model id with other values need to update.
        """

        try:
            restricted_fields = [
                'huggingFace_model_name', 'model_location', 'user']
            for field in restricted_fields:
                if field in request.data:
                    return Response({'error': f'Updating {field} is not allowed.'}, status=status.HTTP_400_BAD_REQUEST)
            id = request.data.get('id', None)
            if not id:
                return missing_field_error('id')
            model_info = ModelInfo.objects.get(id=id, user=request.user)
            if model_info.user != request.user:
                return Response({'error': "You do not have permission to update this modal."}, status=status.HTTP_403_FORBIDDEN)
            # Update the ModelInfo instance
            serializer = self.get_serializer(
                model_info, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()

                return Response({'message': 'LLM Model info update successfully'})
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except ModelInfo.DoesNotExist:
            return Response({'error': 'LLM Model info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: ModelInfoAPIView update error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, *args, **kwargs):
        """ 
        delete Model information
        request body : Model id 
        """

        try:
            id = request.data.get('id', None)
            if not id:
                return missing_field_error('id')
            model_info = ModelInfo.objects.get(id=id)

            # Check if the user has permission to delete the character
            if model_info.user != request.user:
                return Response({'error': "You do not have permission to delete this modal."}, status=status.HTTP_403_FORBIDDEN)
            model_info.delete()
            return Response({'message': 'LLM Model info deleted successfully'})
        except ModelInfo.DoesNotExist:
            return Response({'error': 'LLM Model info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: ModelInfoAPIView delete error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ModelInfoByIDView(APIView):
    """Get Modal Info by id View"""

    permission_classes = [IsAuthenticated, IsValidUser]

    def post(self, request, *args, **kwargs):
        """ 
        Fetch modal information with model id
        """
        try:
            if request.user.is_authenticated:
                id = request.data.get('id')
                if not id:
                    return missing_field_error('id')
                queryset = ModelInfo.objects.filter(Q(id=request.data['id'], user=request.user) | Q(
                    id=request.data['id'], is_public=True))
                serializer = ModelInfoListSerializer(
                    queryset, many=True)
                if not queryset.exists():
                    return Response({'error': 'No modal found with this id'})
                return Response(serializer.data)
        except ModelInfo.DoesNotExist:
            return Response({'error': 'Modal Info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: ModelInfoByIDView post error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetUserCreatedModals(generics.ListAPIView):
    """Get Modal Info of requested user"""

    permission_classes = [IsAuthenticated, IsValidUser]
    serializer_class = ModelInfoListSerializer

    def list(self, request, *args, **kwargs):
        """ 
        Fetch Model information
        """
        try:
            queryset = ModelInfo.objects.filter(user=request.user)
            if not queryset.exists():
                return Response({'error': 'No modal found for this id'})
            serializer = ModelInfoListSerializer(queryset, many=True)
            return Response(serializer.data)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: ModelInfoAPIView list error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PublicCharacterInfoView(APIView):
    # permission_classes = [IsAuthenticated, IsValidUser]

    def get(self, request, *args, **kwargs):
        """ For fetch the all public character info """

        try:
            queryset = CharacterInfo.objects.filter(
                character_visibility="public")
            if not queryset:
                return Response({'error': 'No data found'})
            serializer = PublicCharacterInfoSerializer(queryset, many=True)
            return Response(serializer.data)
        except Exception as error:
            logger.info(
                f"{datetime.now()} :: PublicCharacterInfoView get error :: {error}")
            return Response({'error': str(error)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CharacterInfoView(generics.ListCreateAPIView, generics.RetrieveUpdateDestroyAPIView):
    """Create Character Info View"""

    permission_classes = [IsAuthenticated, IsValidUser]
    serializer_class = CharacterInfoSerializer

    def get_serializer_context(self):
        """
        Extra context provided to the serializer class.
        """
        context = super().get_serializer_context()
        context.update({
            "user": self.request.user
        })
        return context

    def create(self, request, *args, **kwargs):
        try:
            request_data = request.data.copy()
            if not request_data.get('tags'):
                return missing_field_error('tags')

            tag_list = request_data.pop('tags')[0]
            tag_list = json.loads(str(tag_list))
            model_id = request_data.get('model_id')
            if not model_id:
                return missing_field_error('model_id')

            # Check if the user is the owner or the model is public
            queryset = ModelInfo.objects.filter(id=model_id).filter(
                Q(user=request.user) | Q(is_public=True))
            if model_id:
                if not queryset.exists():
                    raise Http404("This model is private, not accessible.")
            serializer = self.get_serializer(data=request_data)
            if serializer.is_valid():
                for tag_obj in tag_list:
                    tag = Tag.objects.get(id=tag_obj)
                    serializer.validated_data['tags'].append(tag)
                serializer.save()
                return Response({'message': 'success', 'data': serializer.data}, status=status.HTTP_200_OK)
            else:
                errors = serializer.errors
                return Response({'error': errors}, status=status.HTTP_400_BAD_REQUEST)
        except Http404 as e:
            return Response({'error': str(e)}, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: CharacterInfoView create error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def list(self, request, *args, **kwargs):
        """ 
        Fetch Character information with the visibility = public
        """
        try:
            if request.user.is_authenticated:
                queryset = CharacterInfo.objects.filter(user=request.user)

                serializer = UserCreatedCharacterInfoSerializer(
                    queryset, many=True)
                if not queryset.exists():
                    return Response({'error': 'No characters found for the user'})
                return Response(serializer.data)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: CharacterInfoView list error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def update(self, request, *args, **kwargs):
        """ 
        Update Character information
        request body: Character id with other values need to update
        """

        try:
            tag_list = None
            id = request.data.get('id', None)
            if not id:
                return missing_field_error('id')

            character_info = CharacterInfo.objects.get(id=id)

            # Check if the user has permission to delete the character
            if character_info.user != request.user:
                return Response({'error': "You do not have permission to update this character."}, status=status.HTTP_403_FORBIDDEN)
            # Use _id for direct foreign key relationship
            model_id = character_info.model_id_id
            queryset = ModelInfo.objects.filter(id=model_id).filter(
                Q(user=request.user) | Q(is_public=True))
            if not queryset.exists():
                raise Http404("This model is private, not accessible.")

            request_data = request.data.copy()
            # Check if 'tags' is provided and not empty
            if 'tags' in request_data:
                tag_list = request_data.pop('tags')[0]
                if not tag_list:
                    return Response({'error': {
                        "tags": [
                            "This field cannot be blank during update."
                        ]
                    }}, status=status.HTTP_400_BAD_REQUEST)
                tag_list = json.loads(str(tag_list))
                # Check if tags are provided but blank
                if not tag_list:
                    return Response({'error': {
                        "tags": [
                            "This field cannot be blank during update."
                        ]
                    }}, status=status.HTTP_400_BAD_REQUEST)

            # Check if 'model_id' is provided and not empty
            if 'model_id' in request_data:
                model_id = request_data.get('model_id')
                if not model_id:
                    return missing_field_error('model_id')

                # Check if the user is the owner or the model is public
                queryset = ModelInfo.objects.filter(id=model_id).filter(
                    Q(user=request.user) | Q(is_public=True))
                if not queryset.exists():
                    raise Http404("This model is private, not accessible.")
            else:
                # If 'model_id' is not provided, retain the existing value
                request_data['model_id'] = model_id

            # serializer = self.get_serializer(character_info, data=request_data)
            serializer = self.get_serializer(
                character_info, data=request_data, partial=True)

            if serializer.is_valid():
                ser = serializer.save()
                if tag_list:
                    for tag_obj in tag_list:
                        tag = Tag.objects.get(id=tag_obj)
                        ser.tags.add(tag)

                return Response({'message': 'character info updated successfully'})

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except CharacterInfo.DoesNotExist:
            return Response({'error': 'character info not found'}, status=status.HTTP_404_NOT_FOUND)

        except Http404 as e:
            return Response({'error': str(e)}, status=status.HTTP_403_FORBIDDEN)

        except Exception as e:
            logger.info(
                f"{datetime.now()} :: CharacterInfoView update error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, *args, **kwargs):
        """ 
        delete Character information
        request body: Character id 
        """
        try:
            id = request.data.get('id', None)
            if not id:
                return missing_field_error('id')
            character_info = CharacterInfo.objects.get(id=id)

            # Check if the user has permission to delete the character
            if character_info.user != request.user:
                return Response({'error': "You do not have permission to delete this character."}, status=status.HTTP_403_FORBIDDEN)

            character_info.delete()
            return Response({'message': 'Character info deleted successfully'})
        except CharacterInfo.DoesNotExist:
            return Response({'error': 'Character info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: CharacterInfoView delete error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TagListInfoView(generics.ListAPIView):
    """ Tag List View"""

    def list(self, request, *args, **kwargs):
        try:
            queryset = Tag.objects.all()
            serializer = CharacterTagInfoSerializer(queryset, many=True)
            return Response(serializer.data)
        except Exception as e:
            logger.info(f"{datetime.now()} :: TagInfoView update error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TagInfoView(generics.ListCreateAPIView, generics.RetrieveUpdateDestroyAPIView):
    """ Tag Info View"""

    permission_classes = [IsAuthenticated, IsValidUser]
    serializer_class = TagInfoSerializer

    def get_serializer_context(self):
        """
        Extra context provided to the serializer class.
        """

        context = super().get_serializer_context()
        context.update({
            "user": self.request.user
        })
        return context

    def list(self, request, *args, **kwargs):
        """all tags list"""
        try:
            queryset = Tag.objects.all()
            if not queryset:
                return Response({'error': 'No tags found'})
            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)
        except Exception as e:
            logger.info(f"{datetime.now()} :: TagInfoView update error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def update(self, request, *args, **kwargs):
        """ 
        update Tag information
        request body : id
        """

        try:
            id = request.data.get('id', None)
            if not id:
                return missing_field_error('id')
            tag_name = request.data.get('tag_name', None)
            if not tag_name:
                return missing_field_error('tag_name')
            tag_info = Tag.objects.get(id=id)
            # Check if the user has permission to delete the character
            if tag_info.user != request.user:
                return Response({'error': "You do not have permission to update this tag."}, status=status.HTTP_403_FORBIDDEN)
            serializer = self.get_serializer(tag_info, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({'message': 'Tag info update successfully'})
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Tag.DoesNotExist:
            return Response({'error': 'Tag info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(f"{datetime.now()} :: TagInfoView update error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, *args, **kwargs):
        """ 
        delete Tag information
        request body: id
        """
        try:
            id = request.data.get('id', None)
            if not id:
                return missing_field_error('id')
            tag_info = Tag.objects.get(id=id)

            # Check if the user has permission to delete the tag
            if tag_info.user != request.user:
                return Response({'error': 'You do not have permission to delete this tag.'}, status=status.HTTP_403_FORBIDDEN)

            tag_info.delete()
            return Response({'message': 'Tag info deleted successfully'})
        except Tag.DoesNotExist:
            return Response({'error': 'Tag info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(f"{datetime.now()} :: TagInfoView delete error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RoomInfoChatView(generics.ListCreateAPIView, generics.RetrieveUpdateDestroyAPIView):
    """For Room Info class view"""

    permission_classes = [IsAuthenticated, IsValidUser]
    serializer_class = RoomInfoChatSerializer

    def create(self, request, *args, **kwargs):
        try:
            character = CharacterInfo.objects.get(id=request.data['character'])
            chat = ChatRoom.objects.create(
                user=request.user, character=character)
            if chat.group_name is None:
                chat.group_name = chat.get_group_name
                chat.save()
            if chat.character.initial_message is not None:
                chat_mag = ChatMessage.objects.create(
                    chat=chat, character_message=chat.character.initial_message)
                chat_mag.save()
            serializer = self.get_serializer(chat)
            return Response({'message': 'success', 'data': serializer.data}, status=status.HTTP_200_OK,)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: RoomInfoChatView create error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def list(self, request, *args, **kwargs):
        try:
            if request.user.is_authenticated:
                queryset = ChatRoom.objects.filter(user=request.user)
                serializer = self.get_serializer(queryset, many=True)
                return Response({'message': 'success', 'data': serializer.data}, status=status.HTTP_200_OK,)

            msg = "User information not found"
            return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            logger.info(
                f"{datetime.now()} :: RoomInfoChatView list error :: {error}")
            msg = "Please provide valid user information"
            return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        """ 
        update room information
        request body : room_id
        """

        try:
            room_id = request.data.get('room_id', None)
            try:
                request.data.pop('user_id')
                request.data.pop('character_id')
            except:
                pass

            if not room_id:
                return missing_field_error('room_id')
            queryset = ChatRoom.objects.get(room_id=room_id)
            # Check if the user has permission to delete the character
            if queryset.user != request.user:
                return Response({'error': "You do not have permission to update this Room Info."}, status=status.HTTP_403_FORBIDDEN)
            serializer = self.get_serializer(queryset, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({'message': 'Room info update successfully'})
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except ChatRoom.DoesNotExist:
            return Response({'error': 'Room info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: RoomInfoChatView updated error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, *args, **kwargs):
        """ 
        delete room information
        request body : room_id
        """

        try:
            room_id = request.data.get('room_id', None)
            if not room_id:
                return missing_field_error('room_id')
            queryset = ChatRoom.objects.get(room_id=room_id)
            # Check if the user has permission to delete the character
            if queryset.user != request.user:
                return Response({'error': "You do not have permission to delete this Room Info."}, status=status.HTTP_403_FORBIDDEN)
            queryset.delete()
            return Response({'message': 'Room info deleted successfully'})

        except ChatRoom.DoesNotExist:
            return Response({'error': 'Room info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: RoomInfoChatView delete error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ChatMessageView(generics.RetrieveUpdateDestroyAPIView, APIView):
    """For Chat Message class view"""

    permission_classes = [IsAuthenticated, IsValidUser]
    serializer_class = ChatMessageSerializer

    def post(self, request, *args, **kwargs):
        """ 
        Fetch room information
        request body : room_id
        """

        try:
            chat = ChatRoom.objects.filter(room_id=request.data['room_id'])
            if chat.exists():
                chat = chat.first()
                queryset = ChatMessage.objects.filter(chat=chat)
                serializer = self.get_serializer(queryset, many=True)

                return Response({'message': 'success', 'data': serializer.data}, status=status.HTTP_200_OK,)
        except Exception as error:
            logger.info(
                f"{datetime.now()} :: ChatMessageView list error :: {error}")
            msg = "Please provide valid room id"
            return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        """ 
        Fetch room information
        request body : message_id with other values need to update
        """

        try:
            message_id = request.data.get('message_id', None)

            if not message_id:
                return missing_field_error('message_id')
            queryset = ChatMessage.objects.get(id=message_id)
            serializer = self.get_serializer(queryset, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({'message': 'Chat Message update successfully'})
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except ChatMessage.DoesNotExist:
            return Response({'error': 'Chat Message not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: ChatMessageView update error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, *args, **kwargs):
        """ 
        Fetch room information
        request body : message_id
        """

        try:
            message_id = request.data.get('message_id', None)
            if not message_id:
                return missing_field_error('message_id')
            queryset = ChatMessage.objects.get(id=message_id)
            queryset.delete()
            return Response({'message': 'Chat Message deleted successfully'})

        except ChatMessage.DoesNotExist:
            return Response({'error': 'Chat Message not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: ChatMessageView delete error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CallLLMView(APIView):
    """For Call LLM Model class view"""
    permission_classes = [IsAuthenticated, IsValidUser]
    serializer_class = CallLLMSerializer

    def post(self, request):
        """Implement LLM Model Post method"""

        try:
            user_msg = request.data['message']
            user = CustomUser.objects.filter(id=request.data['user_id'])
            if user.exists():
                self.user = user.first()
                self.character = CharacterInfo.objects.filter(
                    id=request.data['character_id']).first()
                self.chat, created = ChatRoom.objects.get_or_create(
                    user=self.user, character=self.character)
                if self.chat.group_name is None:
                    self.chat.group_name = self.chat.get_group_name
                    self.chat.save()
                character_attribute = self.set_character_info()
            self.conversation = start_model_llama2(character_attribute)
            self.response_LLM(user_msg)
            return Response({'message': 'success'}, status=status.HTTP_200_OK,)
        except Exception as error:
            print(error)
            msg = "Please provide valid user and character information"
            return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)

    def set_character_info(self):
        custom_character_attribute = {}
        custom_character_attribute['charName'] = self.character.character_name
        custom_character_attribute['Short_Bio'] = self.character.short_bio
        custom_character_attribute["Gender"] = self.character.character_gender
        custom_character_attribute['initial_message'] = self.character.initial_message
        character_attribute_list = self.character.prompt.lower().strip().split(',\n')
        for i in character_attribute_list:
            custom_character_attribute[i.split(":")[0]] = i.split(":")[1]
        print(custom_character_attribute)
        return custom_character_attribute

    def response_LLM(self, sender_user_message):

        response_instance = self.create_msg(self.chat, sender_user_message)
        response = self.conversation.invoke(sender_user_message)
        character_message = response["response"].replace("\n\n", "\n")
        response_instance.character_message = character_message
        response_instance.save()

        self.sender_profile_pic = self.user.profile_image.url if self.user.profile_image else None
        self.character_profile_pic = self.character.image.url if self.character.image else None

        response_data = {
            'type': 'chat_message',
            'message_id': response_instance.id,
            'group_name': self.chat.get_group_name,
            'sender_user_message': sender_user_message,
            'character_message': character_message,

            'sender_user_id': self.user.id,
            'sender_email': self.user.email,
            'sender_profile_pic': self.sender_profile_pic,

            'character_id': self.character.id,
            'character_name': self.character.character_name,
            'character_profile_pic': self.character_profile_pic,
        }
        return response_data

    def create_msg(self, chatroom, user_msg):
        """Storing user chat data into database"""
        try:
            if user_msg is not None:
                chat_mag = ChatMessage.objects.create(
                    chat=chatroom, user_message=user_msg)
                chat_mag.save()
                print('created', chat_mag.id)
                return chat_mag
        except Exception as e:
            Response(f"{e} error occurs")


class FeedbackView(generics.ListCreateAPIView):
    """For Feedback class view"""

    permission_classes = [IsAuthenticated, IsValidUser]
    serializer_class = FeedbackSerializer

    def get_serializer_context(self):
        """
        Extra context provided to the serializer class.
        """

        context = super().get_serializer_context()
        context.update({
            "user": self.request.user
        })
        return context

    def list(self, request, *args, **kwargs):
        try:
            if request.user.is_authenticated:
                queryset = Feedback.objects.filter(user=request.user)
                serializer = self.get_serializer(queryset, many=True)
                return Response({'message': 'success', 'data': serializer.data}, status=status.HTTP_200_OK,)
            msg = "User information not found"
            return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            logger.info(
                f"{datetime.now()} :: FeedbackView list error :: {error}")
            msg = "Please provide valid user information"
            return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(generics.ListAPIView, generics.RetrieveUpdateAPIView):
    """For User Profile class view"""

    permission_classes = [IsAuthenticated, IsValidUser]
    serializer_class = UserProfileInfoSerializer

    def list(self, request, *args, **kwargs):
        try:
            if request.user.is_authenticated:
                queryset = CustomUser.objects.filter(id=request.user.id)
                serializer = self.get_serializer(queryset, many=True)
                return Response({'message': 'success', 'data': serializer.data}, status=status.HTTP_200_OK,)

            msg = "User information not found"
            return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            logger.info(
                f"{datetime.now()} :: UserProfileView list error :: {error}")
            msg = "Please provide valid user information"
            return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        """ 
        update user profile information
        """

        try:
            if request.user.is_authenticated:
                queryset = CustomUser.objects.get(id=request.user.id)
                serializer = self.get_serializer(
                    instance=queryset, data=request.data)
                if serializer.is_valid():
                    serializer.save()
                    return Response({'message': 'User Profile updated successfully'})
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            msg = "User information not found"
            return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User Profile not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: UserProfileView update error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CharacterInfoByIDView(APIView):
    """Get Character Info by id View"""

    permission_classes = [IsAuthenticated, IsValidUser]

    def post(self, request, *args, **kwargs):
        """ 
        Fetch Character information with character id
        """
        try:
            if request.user.is_authenticated:
                id = request.data['character_id']
                if not id:
                    return missing_field_error('character_id')
                queryset = CharacterInfo.objects.filter(
                    id=request.data['character_id'])
                serializer = UserCreatedCharacterInfoSerializer(
                    queryset, many=True)
                if not queryset.exists():
                    return Response({'error': 'No character found with this id'})
                return Response(serializer.data)
        except CharacterInfo.DoesNotExist:
            return Response({'error': 'Character Info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: CharacterInfoByIDView post error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LorebookInfoView(generics.ListAPIView, generics.RetrieveUpdateDestroyAPIView):
    """For lorebook Info class view"""

    permission_classes = [IsAuthenticated, IsValidUser]
    serializer_class = LorebookInfoSerializer

    def list(self, request, *args, **kwargs):
        try:
            if request.user.is_authenticated:
                queryset = Lorebook.objects.filter(user=request.user)
                serializer = self.get_serializer(queryset, many=True)
                return Response({'message': 'success', 'data': serializer.data}, status=status.HTTP_200_OK,)

            msg = "User information not found"
            return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            logger.info(
                f"{datetime.now()} :: LorebookInfoView list error :: {error}")
            msg = "Please provide valid user information"
            return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        """ 
        update lorebook information
        request body : id
        """

        try:
            id = request.data.get('id', None)
            if not id:
                return missing_field_error('id')
            queryset = Lorebook.objects.get(id=id)
            if queryset.user != request.user:
                return Response({'error': "You do not have permission to update this lorebook."}, status=status.HTTP_403_FORBIDDEN)
            serializer = self.get_serializer(queryset, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({'message': 'Lorebook info updated successfully'})
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Lorebook.DoesNotExist:
            return Response({'error': 'Lorebook info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: LorebookInfoView updated error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, *args, **kwargs):
        """ 
        delete lorebook information
        request body : id
        """

        try:
            id = request.data.get('id', None)
            if not id:
                return missing_field_error('id')
            queryset = Lorebook.objects.get(id=id)
            if queryset.user != request.user:
                return Response({'error': "You do not have permission to delete this lorebook."}, status=status.HTTP_403_FORBIDDEN)
            queryset.delete()
            return Response({'message': 'Lorebook info deleted successfully'})

        except Lorebook.DoesNotExist:
            return Response({'error': 'Lorebook info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: LorebookInfoView delete error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class EntryInfoView(generics.ListAPIView, generics.RetrieveUpdateDestroyAPIView):
    """For lorebook entry info class view"""

    permission_classes = [IsAuthenticated, IsValidUser]
    serializer_class = EntryInfoSerializer

    def list(self, request, *args, **kwargs):
        try:
            if request.user.is_authenticated:
                queryset = LorebookEntries.objects.filter(user=request.user)
                serializer = self.get_serializer(queryset, many=True)
                return Response({'message': 'success', 'data': serializer.data}, status=status.HTTP_200_OK,)

            msg = "User information not found"
            return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            logger.info(
                f"{datetime.now()} :: LorebookInfoView list error :: {error}")
            msg = "Please provide valid user information"
            return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        """ 
        update lorebook information
        request body : id
        """

        try:
            id = request.data.get('id', None)
            if not id:
                return missing_field_error('id')
            queryset = LorebookEntries.objects.get(id=id)
            if queryset.user != request.user:
                return Response({'error': "You do not have permission to update this lorebook."}, status=status.HTTP_403_FORBIDDEN)
            serializer = self.get_serializer(queryset, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({'message': 'Lorebook Entry info updated successfully'})
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except LorebookEntries.DoesNotExist:
            return Response({'error': 'Lorebook Entry info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: LorebookInfoView updated error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, *args, **kwargs):
        """ 
        delete lorebook information
        request body : id
        """

        try:
            id = request.data.get('id', None)
            if not id:
                return missing_field_error('id')
            queryset = Lorebook.objects.get(id=id)
            if queryset.user != request.user:
                return Response({'error': "You do not have permission to delete this lorebook."}, status=status.HTTP_403_FORBIDDEN)
            queryset.delete()
            return Response({'message': 'Lorebook info deleted successfully'})

        except Lorebook.DoesNotExist:
            return Response({'error': 'Lorebook info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: LorebookInfoView delete error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GuestUserCreateAPIView(generics.CreateAPIView):
    """For guest user creation class view"""
    serializer_class = GuestUserCreateSerializer

    def create_guest_user(self):
        guest_username = f"guest_{random.randint(0000000, 9999999)}"
        guest_email = f"{guest_username}@mail.com"
        guest_user = CustomUser(
            full_name=guest_username,
            username=guest_username,
            email=guest_email,
            is_active=True,
            is_guest=True,
        )
        guest_user.save()
        return guest_user

    def get(self, request, *args, **kwargs):
        try:
            guest_user = self.create_guest_user()
            serializer = self.get_serializer(guest_user)
            return Response({'message': 'Guest user created successfully', 'data': serializer.data, }, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.info(
                f"{datetime.now()} ::  GuestUserCreateAPIView create error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GuestRoomInfoChatView(generics.CreateAPIView):
    """For create Guest Room Info class view"""

    serializer_class = GuestRoomInfoChatSerializer

    def create(self, request, *args, **kwargs):
        try:
            user_id = request.data.get('user_id', None)
            if not user_id:
                return missing_field_error('user_id')
            user = CustomUser.objects.get(id=user_id)
            character_id = request.data.get('character')
            if not character_id:
                return missing_field_error('character_id')
            character = CharacterInfo.objects.get(id=character_id)

            chat = ChatRoom.objects.create(
                user=user, character=character)
            if chat.group_name is None:
                chat.group_name = chat.get_group_name
                chat.save()
            if chat.character.initial_message is not None:
                chat_mag = ChatMessage.objects.create(
                    chat=chat, character_message=chat.character.initial_message)
                chat_mag.save()
            serializer = self.get_serializer(chat)
            return Response({'message': 'success', 'data': serializer.data}, status=status.HTTP_200_OK,)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: RoomInfoChatView create error :: {e}")
            return Response({'error ': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GuestRoomInfoDeleteChatView(generics.DestroyAPIView):
    """For delete Guest Room Info class view"""

    serializer_class = GuestRoomInfoChatSerializer

    def destroy(self, request, *args, **kwargs):
        try:
            room_id = request.data.get('room_id')
            if not room_id:
                return missing_field_error('room_id')
            room = ChatRoom.objects.get(room_id=room_id)
            room.delete()

            return Response({'message': 'Guest room info deleted successfully'}, status=status.HTTP_200_OK)

        except ChatRoom.DoesNotExist:
            return Response({'error': 'Guest room info not found'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            logger.info(
                f"{datetime.now()} :: GuestRoomInfoDeleteChatView destroy error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GuestRoomInfoByIdView(generics.ListAPIView):

    """View for list guest room info by ID"""

    def post(self, request, *args, **kwargs):

        try:
            user_id = request.data.get('user_id')
            if not user_id:
                return missing_field_error('user_id')
            rooms = ChatRoom.objects.filter(user_id=user_id)
            if not rooms.exists():
                return Response({'error': 'No room info found with this user id'})
            serializer = GuestRoomInfoChatSerializer(rooms, many=True)
            return Response(serializer.data)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: GuestRoomInfoByIdView post error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoraModalInfoView(generics.ListCreateAPIView, generics.RetrieveUpdateDestroyAPIView):

    permission_classes = [IsAuthenticated, IsValidUser]
    serializer_class = LoraModelInfoSerializer

    def get_serializer_context(self):
        """
        Extra context provided to the serializer class.
        """
        context = super().get_serializer_context()
        context.update({
            "user": self.request.user
        })
        return context

    def list(self, request, *args, **kwargs):
        """ 
        Fetch Lora Model information
        """
        try:
            # Filter queryset based on user and is_public
            queryset = LoraModelInfo.objects.filter(user=request.user)
            if not queryset.exists():
                return Response({'error': 'No data found'})
            serializer = LoraAdapterSerializer(queryset, many=True)
            return Response({'message': 'success', 'data': serializer.data}, status=status.HTTP_200_OK,)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: LoraModalInfoView list error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def is_valid_dataset(self, dataset):
        """ validate dataset field"""
        # Check if there are at least 50 sets in the dataset
        if len(dataset) < 50:
            return False
        # Check each item in the dataset
        for item in dataset:
            # Check if each item is a dictionary with 'context' and 'response' keys
            if not isinstance(item, dict) or 'context' not in item or 'response' not in item:
                return False
        return True

    def update(self, request, *args, **kwargs):
        """ 
        Update Lora Model information 
        Request body: Lora Model id with other values need to update.
        """

        try:
            id = request.data.get('id', None)
            if not id:
                return missing_field_error('id')
            lora_model_info = LoraModelInfo.objects.get(id=id)
            if lora_model_info.user != request.user:
                return Response({'error': "You do not have permission to update this lora modal."}, status=status.HTTP_403_FORBIDDEN)
            restricted_fields = [
                'lora_model_name', 'base_model_id', 'tuned_model_path', 'user']
            for field in restricted_fields:
                if field in request.data:
                    return Response({'error': f'Updating {field} is not allowed.'}, status=status.HTTP_400_BAD_REQUEST)
            # Validate the 'dataset' field=============================
            if 'dataset' in request.data:
                # dataset = request.data.get('dataset', lora_model_info.dataset)
                dataset = request.data.get('dataset')
                try:
                    dataset = json.loads(dataset)
                except json.JSONDecodeError:
                    raise serializers.ValidationError(
                        {'dataset': 'The dataset is not a valid JSON array.'})
                if not self.is_valid_dataset(dataset):
                    return Response({'error': {
                        "dataset": [
                            "The dataset is not properly formatted or contains less than 50 sets."
                        ]
                    }}, status=status.HTTP_400_BAD_REQUEST)

            # Update the loraModelInfo instance
            serializer = self.get_serializer(
                lora_model_info, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                fields_affecting_status = [
                    'dataset', 'num_train_epochs', 'per_device_train_batch_size',
                    'learning_rate', 'warmup_steps', 'optimizer',
                    'lr_scheduler_type', 'gradient_accumulation_steps',
                    'lora_alpha', 'lora_dropout', 'lora_r', 'lora_bias'
                ]
                if any(field in request.data for field in fields_affecting_status):
                    if LoraTrainingStatus.objects.filter( lora_model_info=lora_model_info).exists():
                        lora_training_status_instance = LoraTrainingStatus.objects.get(
                            lora_model_info=lora_model_info)
                        lora_training_status_instance.current_status = 'pending'
                        lora_training_status_instance.lora_training_error = ' '
                        lora_training_status_instance.save()

                return Response({'message': 'Lora Model info updated successfully'}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except LoraModelInfo.DoesNotExist:
            return Response({'error': 'Lora Model info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: LoraModalInfoView update error :: {e}")
            return Response({'error': f'unexpected error found: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, *args, **kwargs):
        """ 
        delete Model information
        request body : Model id 
        """

        try:
            id = request.data.get('id', None)
            if not id:
                return missing_field_error('id')
            lora_model_info = LoraModelInfo.objects.get(id=id)

            # Check if the user has permission to delete the modal
            if lora_model_info.user != request.user:
                return Response({'error': "You do not have permission to delete this lora modal."}, status=status.HTTP_403_FORBIDDEN)
            # if not lora_model_info.is_public:
            #     return Response({'error': "You can only delete private Lora Modals."}, status=status.HTTP_403_FORBIDDEN)
            lora_model_info.delete()
            return Response({'message': 'Lora Model info deleted successfully'})
        except LoraModelInfo.DoesNotExist:
            return Response({'error': 'Lora Model info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: LoraModalInfoView delete error :: {e}")
            return Response({'error': f'unexpected error found: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TrainLoraAdapter(APIView):
    """API view to start Lora Training by id for a user"""

    permission_classes = [IsAuthenticated, IsValidUser]

    def post(self, request, *args, **kwargs):
        try:
            lora_model_id = request.data.get('lora_model_id', None)
            if not lora_model_id:
                return missing_field_error('lora_model_id')
            queryset = LoraModelInfo.objects.get(id=lora_model_id)
            if queryset.user != request.user:
                return Response({'error': "You do not have permission to train this adapter."}, status=status.HTTP_403_FORBIDDEN)
            user_id = request.user.id
            lora_training_status_instance, created = LoraTrainingStatus.objects.get_or_create(
                user_id=user_id,
                lora_model_info_id=lora_model_id,
                defaults={'current_status': 'pending'}
            )
            if not created:
                lora_training_status_instance.current_status = 'pending'
                lora_training_status_instance.lora_training_error = ''
                lora_training_status_instance.save()
            result = fetch_lora_modal_data.delay(user_id, lora_model_id)
            logger.info(
                f"{datetime.now()} :: TrainLoraAdapter - Training started successfully for Lora Model ID: {lora_model_id}")
            return Response({'message': 'Lora adapter training started successfully'}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.exception(
                f"{datetime.now()} :: TrainLoraAdapter - An error occurred: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CurrentLoraModalStatusView(APIView):
    """
    API view to get the current status of a Lora modal.
    """
    permission_classes = [IsAuthenticated, IsValidUser]

    def post(self, request, *args, **kwargs):

        try:
            lora_model_id = request.data.get('lora_model_id', None)
            if not lora_model_id:
                return missing_field_error(lora_model_id)

            lora_model_status = LoraTrainingStatus.objects.filter(
                lora_model_info__id=lora_model_id).first()

            if not lora_model_status:
                return Response({'error': 'No data found'}, status=status.HTTP_404_NOT_FOUND)
            serializer = LoraTrainingStatusSerializer(lora_model_status)
            return Response({'message': 'success', 'data': serializer.data}, status=status.HTTP_200_OK,)

        except Exception as e:
            logger.info(
                f"{datetime.now()} :: CurrentLoraModalStatusView fetch error :: {e}")
            return Response({'error': f'An unexpected error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserAllAdapterListView(generics.ListAPIView):
    """API view to list All Lora Training Status instances for a user"""
    permission_classes = [IsAuthenticated, IsValidUser]
    serializer_class = LoraTrainingStatusSerializer

    def list(self, request, *args, **kwargs):
        try:
            user = request.user
            queryset = LoraTrainingStatus.objects.filter(user=user)
            if not queryset.exists():
                return Response({'error': 'No lora adapters found'}, status=status.HTTP_404_NOT_FOUND)
            serializer = LoraTrainingStatusSerializer(queryset, many=True)
            return Response({'message': 'success', 'data': serializer.data}, status=status.HTTP_200_OK,)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: UserAllAdapterListView list error :: {e}")
            return Response({'error': f'An unexpected error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PublicTrainedAdaptersListView(generics.ListAPIView):
    """API view to list all public adapter details"""
    # permission_classes = [IsAuthenticated, IsValidUser]
    serializer_class = LoraTrainingStatusSerializer

    def list(self, request, *args, **kwargs):
        try:
            queryset = LoraTrainingStatus.objects.filter(
                current_status='completed')

            if not queryset.exists():
                return Response({'message': 'No trained Lora adapters found'}, status=status.HTTP_404_NOT_FOUND)

            serializer = LoraTrainingStatusSerializer(queryset, many=True)
            return Response({'message': 'success', 'data': serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(
                f"{datetime.now()} :: PublicTrainedAdaptersListView list error :: {e}")
            return Response({'error': f'An unexpected error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RunLoraAdapterView(APIView):
    """API view to run lora adapter, lora_model_id and user_text needed to run adapter
    """
    # permission_classes = [IsAuthenticated, IsValidUser]

    def post(self, request, *args, **kwargs):
        try:
            lora_model_id = request.data.get('lora_model_id', None)
            user_text = request.data.get('user_text', None)
            if not lora_model_id:
                return missing_field_error('lora_model_id')

            if not user_text:
                return missing_field_error('user_text')

            lora_model = LoraModelInfo.objects.get(id=lora_model_id)
            if not lora_model:
                return Response({'error': 'This Adapter is no longer available. Please choose another one.'}, status=status.HTTP_404_NOT_FOUND)
            model_info = ModelInfo.objects.get(id=lora_model.base_model_id.id)
            run_lora_adapter_data = {
                'model_param': {
                    'tokenizer': model_info.huggingFace_model_name,
                    'base_model': model_info.huggingFace_model_name,
                    'cache_dir': model_info.model_location,
                    'token': settings.HF_TOKEN,
                },
                'adapter_path': lora_model.tuned_model_path,
                'text': user_text
            }

            response, is_error = RunLoraAdapter().run_adapter(run_lora_adapter_data)
            if is_error:
                logger.error(
                    f"{datetime.now()} :: RunLoraAdapter error :: {response}")
                return Response({'error': response}, status=status.HTTP_200_OK,)
            else:
                return Response({'response_message': response}, status=status.HTTP_200_OK,)
        except Exception as e:
            logger.error(
                f"{datetime.now()} :: RunLoraAdapter error :: {e}")
            return Response({'error': f'An unexpected error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AdapterRoomInfoChatView(generics.ListCreateAPIView, generics.RetrieveUpdateDestroyAPIView):
    """For adapter Room Info class view"""

    permission_classes = [IsAuthenticated, IsValidUser]
    serializer_class = AdapterRoomInfoChatSerializer

    def create(self, request, *args, **kwargs):
        """create  adapter room information, with adapter id"""

        try:
            adapter = request.data.get('adapter', None)
            if not adapter:
                return missing_field_error('adapter')
            try:
                adapter = LoraModelInfo.objects.get(id=adapter)
            except LoraModelInfo.DoesNotExist:
                return Response({'error': 'Lora Model not found'}, status=status.HTTP_404_NOT_FOUND)

            chat = AdapterChatRoom.objects.create(
                user=request.user, adapter=adapter)
            if chat.group_name is None:
                chat.group_name = chat.get_group_name
                chat.save()

            serializer = self.get_serializer(chat)
            return Response({'message': 'success', 'data': serializer.data}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.info(
                f"{datetime.now()} :: AdapterRoomInfoChatView create error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def list(self, request, *args, **kwargs):
        """list all adapter room information."""

        try:
            if request.user.is_authenticated:
                queryset = AdapterChatRoom.objects.filter(user=request.user)
                serializer = self.get_serializer(queryset, many=True)
                if serializer.data:
                    return Response({'message': 'success', 'data': serializer.data}, status=status.HTTP_200_OK,)
                else:
                    return Response({'error': 'No data found'}, status=status.HTTP_200_OK,)

            msg = "User information not found"
            return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            logger.info(
                f"{datetime.now()} :: AdapterRoomInfoChatView list error :: {error}")
            msg = "Please provide valid user information"
            return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        """Update adapter room information. Request body: adapter_room_id."""
        try:
            adapter_room_id = request.data.get('adapter_room_id', None)

            if not adapter_room_id:
                return missing_field_error('adapter_room_id')

            queryset = AdapterChatRoom.objects.get(
                adapter_room_id=adapter_room_id)

            if queryset.user != request.user:
                return Response({'error': "You do not have permission to update this Room Info."}, status=status.HTTP_403_FORBIDDEN)
            serializer = self.get_serializer(queryset, data=request.data)

            if serializer.is_valid():
                serializer.save()
                return Response({'message': 'Adapter Room info updated successfully'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Validation error', 'details': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except AdapterChatRoom.DoesNotExist:
            return Response({'error': 'Adapter Room info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: AdapterRoomInfoChatView updated error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, *args, **kwargs):
        """ 
        delete adapter room information
        request body : adapter_room_id
        """

        try:
            adapter_room_id = request.data.get('adapter_room_id', None)
            if not adapter_room_id:
                return missing_field_error('adapter_room_id')
            queryset = AdapterChatRoom.objects.get(
                adapter_room_id=adapter_room_id)
            # Check if the user has permission to delete the character
            if queryset.user != request.user:
                return Response({'error': "You do not have permission to delete this Room Info."}, status=status.HTTP_403_FORBIDDEN)
            queryset.delete()
            return Response({'message': 'Adapter Room info deleted successfully'})

        except AdapterChatRoom.DoesNotExist:
            return Response({'error': 'Adapter Room info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: AdapterRoomInfoChatView delete error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AdapterChatMessageView(generics.RetrieveUpdateDestroyAPIView, APIView):
    """For adapter Chat Message class view"""

    permission_classes = [IsAuthenticated, IsValidUser]
    serializer_class = AdapterChatMessageSerializer

    def post(self, request, *args, **kwargs):
        """ 
        Create an AdapterChatMessage
        request body: adapter_room_id, user_message, adapter_message 
        """

        try:
            adapter_room_id = request.data.get('adapter_room_id')
            user_message = request.data.get('user_message')
            adapter_message = request.data.get('adapter_message')

            if not adapter_room_id:
                return missing_field_error('adapter_room_id')
            if not user_message:
                return missing_field_error('user_message')
            if not adapter_message:
                return missing_field_error('adapter_message')
            chat_room = AdapterChatRoom.objects.get(
                adapter_room_id=adapter_room_id)

            queryset = AdapterChatMessage.objects.create(
                adapter_chatroom=chat_room,
                user_message=user_message,
                adapter_message=adapter_message
            )

            serializer = self.get_serializer(queryset)
            return Response({'message': 'success', 'data': serializer.data}, status=status.HTTP_201_CREATED)

        except Exception as error:
            logger.info(
                f"{datetime.now()} :: AdapterChatMessageView post error :: {error}")
            msg = "An error occurred while creating the AdapterChatMessage"
            return Response({"error": msg}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def update(self, request, *args, **kwargs):
        """ 
        update room information
        request body : message_id with other values need to update
        """

        try:
            message_id = request.data.get('message_id', None)

            if not message_id:
                return missing_field_error('message_id')
            queryset = AdapterChatMessage.objects.get(id=message_id)
            if queryset.adapter_chatroom.user != request.user:
                return Response({'error': "You do not have permission to update this chat."}, status=status.HTTP_403_FORBIDDEN)
            serializer = self.get_serializer(queryset, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({'message': 'Adapter Chat Message update successfully'})
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except AdapterChatMessage.DoesNotExist:
            return Response({'error': 'Adapter Chat Message not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: AdapterChatMessageView update error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, *args, **kwargs):
        """ 
        delete adapter room information
        request body : message_id
        """

        try:
            message_id = request.data.get('message_id', None)
            if not message_id:
                return missing_field_error('message_id')
            queryset = AdapterChatMessage.objects.get(id=message_id)
            if queryset.adapter_chatroom.user != request.user:
                return Response({'error': "You do not have permission to delete this chat."}, status=status.HTTP_403_FORBIDDEN)
            queryset.delete()
            return Response({'message': 'Adapter Chat Message deleted successfully'})

        except AdapterChatMessage.DoesNotExist:
            return Response({'error': 'Adapter Chat Message not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.info(
                f"{datetime.now()} :: AdapterChatMessageView delete error :: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class MetaMaskTransactionView(generics.ListCreateAPIView, generics.DestroyAPIView):
    """View for user's metamask transaction details"""
    permission_classes = [IsAuthenticated, IsValidUser]
    serializer_class = MetaMaskTransactionSerializer

    def get_serializer_context(self):
        """
        Extra context provided to the serializer class.
        """
        context = super().get_serializer_context()
        context.update({
            "user": self.request.user
        })
        return context

    def list(self, request, *args, **kwargs):
        """ list user's metamask transaction details"""
        try:
            queryset = MetaMaskTransactionHistory.objects.filter(
                user=request.user)
            if not queryset.exists():
                return Response({'error': 'No transaction details found'}, status=status.HTTP_404_NOT_FOUND)
            serializer = MetaMaskTransactionSerializer(queryset, many=True)
            return Response({'message': 'success', 'data': serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(
                f"{datetime.now()} :: MetaMaskTransactionView list error :: {e}")
            return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, *args, **kwargs):
        """ 
        delete metamask transaction details by ID or all related to the user
        """
        try:
            id = request.data.get('id', None)
            if id:
                # Delete transaction detail by ID if provided
                transaction_info = MetaMaskTransactionHistory.objects.get(
                    id=id)

                # Check if the user has permission to delete the detail
                if transaction_info.user != request.user:
                    return Response({'error': "You do not have permission to delete this transaction detail."}, status=status.HTTP_403_FORBIDDEN)
                transaction_info.delete()
                return Response({'message': 'MetaMask Transaction info deleted successfully'}, status=status.HTTP_200_OK)
            else:
                # Delete all transaction details related to the user
                queryset = MetaMaskTransactionHistory.objects.filter( user=request.user)
                if not queryset.exists():
                    return Response({'error': 'No transaction details found'}, status=status.HTTP_404_NOT_FOUND)
                queryset.delete()
                return Response({'message': 'All MetaMask Transaction info deleted successfully'}, status=status.HTTP_200_OK)
        except MetaMaskTransactionHistory.DoesNotExist:
            return Response({'error': 'MetaMask Transaction info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(
                f"{datetime.now()} :: MetaMaskTransactionView delete error :: {e}")
            return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# get_captcha


class UserCaptchaView(APIView):
    """API view to generate and retrieve user captcha."""

    address_param = openapi.Parameter('web3_address', openapi.IN_QUERY,
                                      description="web3 address", type=openapi.TYPE_STRING, required=True)

    @swagger_auto_schema(manual_parameters=[address_param])
    def post(self, request, *args, **kwargs):
        try:
            content = {}
            # get the address from params
            address = request.data.get('web3_address')
            if address is None or not address.strip():  # Check if address is empty or contains only whitespace
                return missing_field_error('web3_address')
            try:
                # Try to retrieve the user if it exists
                user_obj = CustomUser.objects.get(web3_address=address)
            except CustomUser.DoesNotExist:
                # If the user does not exist, create one
                email = f'metamask{get_random_string(3)}@mail.com'
                user_obj = CustomUser.objects.create(
                    email=email, web3_address=address)

            # delete all the old captchas of this user
            UserCaptcha.objects.filter(user=user_obj).delete()
            # create a new captcha
            captcha = get_random_string()
            # assign it
            user_captcha_obj = UserCaptcha(
                captcha=captcha,
                user=user_obj
            )
            user_captcha_obj.save()

            content["data"] = {"captcha": user_captcha_obj.captcha}
            content["message"] = "successfully executed!"
            return Response(content, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(
                f"{datetime.now()} :: UserCaptchaView error :: {e}")
            return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class MetamaskLoginView(APIView):
    """Metamask login view"""

    def post(self, request):
        """Handle Metamask login"""

        data = request.data
        if data.get('web3_address') is None or not data['web3_address'].strip():
            return missing_field_error('web3_address')

        if data.get('signature') is None or not data['signature'].strip():
            return missing_field_error('signature')
        print(data["signature"], data["web3_address"])
        try:
            # Check if user exists
            if CustomUser.objects.filter(web3_address=data["web3_address"]).exists():
                user = CustomUser.objects.get(
                    web3_address=data["web3_address"])

                # Get the captcha from the database
                if UserCaptcha.objects.filter(user=user).exists():
                    captcha = UserCaptcha.objects.get(user=user)
                    message = encode_defunct(text=captcha.captcha)

                    # Derive public key using the provided signature and captcha
                    pub2 = w3.eth.account.recover_message(
                        message, signature=data["signature"])

                    # Check if public key matches the user's Metamask address
                    if user.web3_address == pub2:
                        user.web3_address = data["web3_address"]
                        user.is_active = True
                        user.save()
                        serializer = CustomUserSerializer(user)
                        refresh = RefreshToken.for_user(user)
                        return Response({'message': 'success', 'data': serializer.data,
                                        'refresh': str(refresh), 'access': str(refresh.access_token)}, status=status.HTTP_200_OK, )
                    else:
                        return Response({'error': 'Public key does not match the Metamask address.'}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({'error': 'Captcha not found for the user.'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'error': 'User not found.'}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(
                f"{datetime.now()} :: MetamaskLoginView post error :: {e}")
            return Response({'error': 'An unexpected error occurred.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
