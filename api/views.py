from BackendAssignment.settings import *
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework.response import Response
from api.models import User
from rest_framework.views import APIView
from django.contrib.auth import  login
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from api.serializer import UserCreateUpdateSerializer, UserLoginDetailSerializer, PostSerializer
from rest_framework_jwt.settings import api_settings
import jwt
from api.models import User, UserSession
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER



class SignupView(APIView):
    permission_classes = (AllowAny,)
    
    def post(self, request, format=None):
        """
        Create User/ Signup User
        """
        serializer = UserCreateUpdateSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()

            data =  ({"data":serializer.data, "code":status.HTTP_201_CREATED, "message":"User Created Successfully"})
            return Response(data, status=status.HTTP_200_OK)
        result =  ({"data":serializer.errors, "code":status.HTTP_400_BAD_REQUEST, "message":"Oops! Something went wrong."})
        return Response(result, status=status.HTTP_200_OK)

class LoginView(APIView):
    permission_classes = (AllowAny,)
    
    def post(self, request, format=None):
        """
        Login
        """
        username = request.data['email']
        username = username.lower()
        password = request.data['password']

    
        user = self.user_authenticate(username, password)
        from rest_framework_jwt.settings import api_settings
        if user is not None:

                login(request, user)

                serializer = UserLoginDetailSerializer(user)

                payload = jwt_payload_handler(user)
                token = jwt.encode(payload, SECRET_KEY)

                user_details = serializer.data
                user_details['token'] = token

                user_session = self.create_update_user_session(user, token, request)
                return Response(({"data": user_details,"code": status.HTTP_200_OK,"message": "LOGIN_SUCCESSFULLY"}), status=status.HTTP_200_OK)
        return Response(({"data": None,"code": status.HTTP_400_BAD_REQUEST, "message": "INVALID_CREDENTIALS"}), status=status.HTTP_200_OK)

    def user_authenticate(self, user_name, password):
            try:
                user = User.objects.get(email=user_name)
                if user.check_password(password):
                    return user # return user on valid credentials
            except User.DoesNotExist:
                try:
                    user = User.objects.get(phone_no=user_name)
                    if user.check_password(password):
                        return user # return user on valid credentials
                except User.DoesNotExist:
                    return None
    def create_update_user_session(self, user, token, request):
        """
        Create User Session
        """
        print(request.headers.get('device-type'))
        print(request.data.get('device_id'))

        user_session = self.get_user_session_object(user.pk, request.headers.get('device-type'), request.data.get('device_id'))

        if user_session is None:
            UserSession.objects.create(
                user = user,
                token = token,
                device_id = request.data.get('device_id'),
                device_type = request.headers.get('device-type'),
                app_version = request.headers.get('app-version')
            )

        else:
            user_session.token = token
            user_session.app_version = request.headers.get('app-version')
            user_session.save()

        return user_session
    
    def get_user_session_object(self, user_id, device_type, device_id=None):
        try:
            if device_id:
                try:
                    return UserSession.objects.get(user=user_id, device_type=device_type, device_id=device_id)
                except UserSession.DoesNotExist:
                    return None

            return UserSession.objects.get(user=user_id, device_type=device_type, device_id=device_id)

        except UserSession.DoesNotExist:
            return None

class CreatePostView(APIView):
    permission_classes = (IsAuthenticated,)
    def post(self, request, format=None):
        request.data['user'] = request.user.id
        serializer = PostSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save ()
            result = ({"data": serializer.data, "code": status.HTTP_201_CREATED, "message": "Post Created Successfully."})
        return Response(result, status=status.HTTP_200_OK)