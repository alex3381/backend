from django.contrib.auth import get_user_model
from rest_framework import permissions, generics, status
from rest_framework.generics import CreateAPIView
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import Util
from rest_framework.response import Response
from .serializers import RegisterSerializer, LoginSerializer


class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data

        # Sending email Verification
        user = User.objects.get(email=user_data [ 'email' ])
        token = RefreshToken.for_user(user).access_token
        return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
