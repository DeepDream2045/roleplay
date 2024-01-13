from django.template.loader import render_to_string
from rest_framework import generics
from rest_framework.views import APIView
from django.contrib import auth
from rest_framework.response import Response
from .serializers import (RegisterSerializer, LoginSerializer, LogoutSerializer,
ForgotPasswordSerializer, ResetPasswordSerializer,MagicLoginSerializer,
CharacterInfoSerializer, ModelInfoSerializer)
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from roleplay_manager.permission import IsValidUser
from rest_framework_simplejwt.tokens import RefreshToken
from .models import CustomUser, TokenRequest, CharacterInfo, ModelInfo
import uuid
import logging
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from .utility import send_email, create_img_url

logger = logging.getLogger(__name__)

class Registraion(APIView):
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
                    return Response({'error':"Email already used"})
                user = serializer.save()
                self.send_email_verification(serializer, user)
                refresh = RefreshToken.for_user(user)
                return Response({"message": 'success', 'data':serializer.data, 'refresh': str(refresh)
                        , 'access': str(refresh.access_token)}, status=status.HTTP_200_OK)

            return Response({"message": "Field error", "data": serializer.errors},
                        status=status.HTTP_400_BAD_REQUEST)
                        
        except Exception:
            logger.error('Field error data not valid')
            return Response({"message": "Field error data not valid", "data": serializer.errors},
                        status=status.HTTP_400_BAD_REQUEST)
    
    def send_email_verification(self, serializer, user):
            if not user.email_confirmation:
                expiration_time= timezone.now() + timezone.timedelta(minutes=30) 
                title = 'Email confirmation mail'
                email = user.email
                token = str(uuid.uuid4())
                encoded_email = email.encode('utf_16', 'strict').hex() 
                token_create=TokenRequest.objects.create(user=user, token=token, expiration_time=expiration_time)
                urls = f"{settings.DASHBOARD_BASE_ROUTE}/email_confirmation/{token}/{encoded_email}/"
                if token_create:
                    body_html = render_to_string(
                            'email_confirmation.html',
                            {'name': user.full_name , 'token':token, 'email':email.encode('utf_16','strict'), 'url':urls}
                        )
                    body_html += ''
                    result = send_email(title, body_html, [email])
                    if result:
                        return Response({'message':'We have sent you a link on email please verify', 'user':serializer.data,},status=status.HTTP_200_OK,)
                return Response({'error':'Error while sending  email for email confirmation', 'user':serializer.data,},status=status.HTTP_200_OK,)
            return Response({'message':'Email already verified!','user':serializer.data,},status=status.HTTP_200_OK)  


class LoginView(APIView):
    """ Login view"""

    def post(self, request):
        """Login view """

        serializer = LoginSerializer(data=request.data)
        try:
            if serializer.is_valid():
                email = serializer.validated_data['email']
                password = serializer.validated_data['password']
                user = auth.authenticate(request, email=email.lower(), password=password)
                if user is None:
                    return Response({'error': "Invalid credentials."})
                if user.is_active:
                    profile_image = ''
                    try:
                        if user.profile_image.url:
                            profile_image = create_img_url(request, user.profile_image.url)
                    except ValueError:
                            profile_image = create_img_url(request, user.profile_image)
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
                            'refresh': str(refresh), 'access': str(refresh.access_token)}
                            , status=status.HTTP_200_OK, )
                return Response({'message': 'user not active', 'data': serializer.errors},status=status.HTTP_400_BAD_REQUEST)
                
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception:
            logger.info("Invalid Email or password")
            return Response({"error": "Invalid Email or password"},status=status.HTTP_400_BAD_REQUEST)


class LogoutView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = (IsAuthenticated, IsValidUser)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response({'errors': serializer.errors},status=status.HTTP_204_NO_CONTENT)


class ForgetPassword(APIView):
    """Forgot password class view"""

    def get(self, request, *args, **kwargs):

        """Get view """
        serializer = ForgotPasswordSerializer()
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        """post view"""
        expiration_time= timezone.now() + timezone.timedelta(minutes=5)
        try:
            user = CustomUser.objects.filter(email=request.data['email']).first()
            if user is not None:
                title = 'Forget Password'
                email = user.email
                token = str(uuid.uuid4())
                token_create=TokenRequest.objects.create(user=user, token=token, expiration_time=expiration_time)
                urls = f"{settings.DASHBOARD_BASE_ROUTE}/reset_password/{token}/"
                if token_create:
                    body_html = render_to_string(
                            'forgot_password.html',
                            {'name': user.full_name , 'token':token, 'url':urls}
                        )
                    body_html += ''
                    result = send_email(title, body_html, [email])
                    return Response({'message':'success'},status=status.HTTP_200_OK,)

            return Response({'error':'Email does not exists!'},status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            print(error)
            msg = "Error while sending  email for forgot password"
            return Response({"error": msg},status=status.HTTP_400_BAD_REQUEST)

            
class ResetPassword(APIView):
    """Reset password class view"""

    def get(self, request, *args, **kwargs):
    
        password_reset = TokenRequest.objects.get(token=request.GET['token'])
        if password_reset.expiration_time < timezone.now():
                return Response({'error':'password_reset_expired'})
        else:
            return Response({"message": 'success'})

    def post(self, request, *args, **kwargs):
        """ reset password post view"""

        password_reset = TokenRequest.objects.get(token=request.data['token'])
        serializer = ResetPasswordSerializer(data = request.data)
        try:
            if password_reset.expiration_time < timezone.now():
                return Response({'error':'password_reset_expired'})
            if serializer.is_valid():
                email = serializer.data.get('email')
                new_password = serializer.data.get('new_password')
                if email:
                    user = CustomUser.objects.filter(email=email).first()
                    if user is None:
                        return Response({'error':'Email does not exists'})
                    user.password = make_password(new_password)
                    user.save()
                    return Response({'message':'Password successfully updated' },status=status.HTTP_200_OK,)
                return Response({'error':'user does not exists'},status=status.HTTP_400_BAD_REQUEST)
        except Exception:
                return Response({'error':'something went wrong'},status=status.HTTP_400_BAD_REQUEST)


class ChangeProfilePictureView(APIView):
    """Change profile image view"""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            user_obj = CustomUser.objects.get(email=request.user)
            if user_obj:
                user_obj.profile_image = request.data['profile_image'] 
                user_obj.save()
                profile_image =''
                try:
                    if user_obj.profile_image.url:
                       profile_image = create_img_url(request, user_obj.profile_image.url)
                       return Response({"message": "Profile changed successfully!", 'profile_image':profile_image})
                except ValueError:
                    profile_image = create_img_url(request, user_obj.profile_image)
                    return Response({"message": "Profile changed successfully!", 'profile_image':profile_image})
            return Response({"error": "User  does not exists!"})

        except CustomUser.DoesNotExist:
            return Response({"error":"User  does not exists!"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as err:
            return Response({"error":"User  does not exists!", 'err': err.__str__()}, status=status.HTTP_400_BAD_REQUEST)


class EmailConfirmation(APIView):
    """For email verification"""

    def post(self, request):
        """Email verification view"""
        
        try:
            email_confirm = TokenRequest.objects.get(token=request.data['token'])
            if email_confirm.expiration_time < timezone.now():
                return Response({'error':'eamil_confirmation_link_expired'})
            email_bytes = bytes.fromhex(request.data['email'])
            decoded_email = email_bytes.decode('utf-16', 'strict')
            user = CustomUser.objects.get(email=decoded_email)
            if not user.email_confirmation :
                user.email_confirmation = True
                user.save()
                return Response({'message':'Email is verified'},status=status.HTTP_200_OK)
            return Response({'error': "Email already verified!"},status=status.HTTP_400_BAD_REQUEST)

        except TokenRequest.DoesNotExist:
            return Response({'error':'token does not exists!'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': "Email does not exists!", 'error_msg': e.__repr__()},status=status.HTTP_400_BAD_REQUEST)


class MagicLoginRequestView(APIView):
    """For Magic login request class view"""

    def post(self, request):
        """Implement logic to send the magic login link to the user's email
        This could involve generating a unique token and sending it in an email"""

        expiration_time= timezone.now() + timezone.timedelta(minutes=10)
        try:
            user = CustomUser.objects.filter(email=request.data['email']).first()
            if not user:
                email= request.data['email'].lower()
                user = CustomUser.objects.create(email=email)

            if user is not None:
                title = 'Sign into Roleplay'
                email = user.email
                token = str(uuid.uuid4())
                token_create=TokenRequest.objects.create(user=user, token=token, expiration_time=expiration_time)
                urls = f"{settings.DASHBOARD_BASE_ROUTE}/login_verify/{token}/"
                if token_create:
                    body_html = render_to_string(
                            'login_mail.html', {'url':urls}
                        )
                    body_html += ''
                    result = send_email(title, body_html, [email])
                    print(token)
                    return Response({'message':'success'},status=status.HTTP_200_OK,)
        except Exception as error:
            print(error)
            msg = "Error while sending email for Login"
            return Response({"error": msg},status=status.HTTP_400_BAD_REQUEST)


class MagicLoginVerifyView(APIView):
    """Magic login verification class view"""

    def post(self, request, *args, **kwargs):
        """ Magic login verification post view"""

        token = TokenRequest.objects.get(token=request.data['token'])
        serializer = MagicLoginSerializer(data=request.data)

        try:
            if token.expiration_time < timezone.now():
                return Response({'error':'token expired'},status=status.HTTP_400_BAD_REQUEST)
            if serializer.is_valid():
            # if serializer.is_valid(raise_exception=True)
                # token = serializer.data.get('token')
                if token:
                    user = CustomUser.objects.filter(id=token.user.id).first()
                    if user is None:
                        return Response({'error':'token expired'},status=status.HTTP_400_BAD_REQUEST)
                    if not user.email_confirmation:
                        user.email_confirmation = True
                        user.is_active = True
                    user.save()
                    profile_image = ''
                    try:
                        if user.profile_image.url:
                            profile_image = create_img_url(request, user.profile_image.url)
                    except ValueError:
                            profile_image = create_img_url(request, user.profile_image)
                    refresh = RefreshToken.for_user(user)
                    response_data = {}
                    response_data['id'] = user.id
                    response_data['full_name'] = user.full_name
                    response_data['email'] = user.email
                    response_data['profile_image'] = profile_image
                    response_data['stay_sign'] = user.stay_sign
                    return Response({'message': 'success', 'data': response_data,
                            'refresh': str(refresh), 'access': str(refresh.access_token)}
                            , status=status.HTTP_200_OK, )
                return Response({'error':'token expired'},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
                logger.error(str(e))
                return Response({'error':'something went wrong'},status=status.HTTP_400_BAD_REQUEST)


class ModelInfoAPIView(generics.ListCreateAPIView, generics.RetrieveUpdateDestroyAPIView):

    permission_classes = [IsAuthenticated, IsValidUser]
    serializer_class = ModelInfoSerializer
    queryset = ModelInfo.objects.all()

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
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    
    def update(self, request, *args, **kwargs):
        try:
            id = request.data.get('id', None)
            model_info = ModelInfo.objects.get(id=id)
            serializer = self.get_serializer(model_info, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({'message': 'LLM Model info update successfully'})
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except ModelInfo.DoesNotExist:
            return Response({'error': 'LLM Model info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def delete(self, request, *args, **kwargs):
        try:
            id = request.data.get('id', None)
            model_info = ModelInfo.objects.get(id=id)
            model_info.delete()
            return Response({'message': 'LLM Model info deleted successfully'})
        except ModelInfo.DoesNotExist:
            return Response({'error': 'LLM Model info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class CharacterInfoView(generics.ListCreateAPIView, generics.RetrieveUpdateDestroyAPIView):
    """Create Character Info View"""

    permission_classes = [IsAuthenticated, IsValidUser]
    serializer_class = CharacterInfoSerializer
    queryset = CharacterInfo.objects.all()

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
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def update(self, request, *args, **kwargs):
        try:
            id = request.data.get('id', None)
            character_info = CharacterInfo.objects.get(id=id)
            serializer = self.get_serializer(character_info, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({'message': 'character info update successfully'})
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except CharacterInfo.DoesNotExist:
            return Response({'error': 'character info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, *args, **kwargs):
        try:
            id = request.data.get('id', None)
            character_info = CharacterInfo.objects.get(id=id)
            character_info.delete()
            return Response({'message': 'character info deleted successfully'})
        except CharacterInfo.DoesNotExist:
            return Response({'error': 'character info not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
