
from django.contrib import auth
from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken
from sqlparse.compat import text_type
from authentications import models

UserModel = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    tokens = serializers.SerializerMethodField()
    password = serializers.CharField(
        style={'input_type': 'password'},
        max_length=128,
        min_length=6,
        write_only=True,
        label="Password"

    )
    confirm_password = serializers.CharField(
        style={'input_type': 'password'},
        label="Confirm Password",
        max_length=128, min_length=6, write_only=True

    )

    # is_staff = serializers.BooleanField(
    #     label="Member of the team",
    #     help_text="Indicates which user is able to access the administration site."
    # )
    #
    # is_superuser = serializers.BooleanField(
    #     label="superuser",
    #     help_text="Indicates that this user has all permissions without explicitly assigning them."
    #
    # )

    class Meta:
        model = models.User
        fields = ( 'email', 'password', 'confirm_password', 'type', 'tokens', )
        extra_kwargs = {
            'password': {'write_only': True},

        }

    def get_tokens(self, user):
        tokens = RefreshToken.for_user(user)
        refresh = text_type(tokens)
        access = text_type(tokens.access_token)
        data = {
            "refresh": refresh,
            "access": access
        }
        return data

    def create(self, validated_data):
        user = models.User(
            email=self.validated_data ['email'],
            # is_staff=self.validated_data['is_staff'],
            # is_superuser=self.validated_data['is_superuser']
        )

        password = self.validated_data['password']
        confirm_password = self.validated_data['confirm_password']

        if password != confirm_password:
            raise serializers.ValidationError({'password': 'Passwords do not match.'})
        user.set_password(password)
        user.save()
        return user
        # user.set_password(validated_data [ 'password' ])
        # user.set_password(validated_data [ 'confirm_password' ])
        #
        # if password != confirm_password:
        #  raise serializers.ValidationError({'password': 'Passwords do not match.'})
        #  user.save()
        #
        #     return user

    # def get_tokens(self, user):
    #     tokens = RefreshToken.for_user(user)
    #     refresh = text_type(tokens)
    #     access = text_type(tokens.access_token)
    #     data = {
    #         "refresh": refresh,
    #         "access": access
    #     }
    #     return data

    # def create(self, validated_data):
    #     user = models.User(
    #         email=validated_data [ 'email' ]
    #     )
    #     user.set_password(validated_data [ 'password' ])
    #     user.set_password(validated_data [ 'confirm_password' ])
    #     user.save()
    #     return user


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=5)
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    # confirm_password = serializers.CharField(allow_blank=False, write_only=True)

    tokens = serializers.SerializerMethodField(read_only=True)

    def get_tokens(self, obj):
        user = UserModel.objects.get(email=obj [ 'email' ])

        return {
            'refresh': user.tokens() [ 'refresh' ],
            'access': user.tokens() [ 'access' ]
        }

    class Meta:
        model = UserModel
        fields = [ 'id', 'email', 'tokens', 'password', 'type' ]

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        user = auth.authenticate(email=email, password=password, )

        if not user:
            raise AuthenticationFailed('Invalid Credentials Provided, try again')

        if not user.is_active:
            raise AuthenticationFailed('Account Disabled, Contact Support')

        if not user.is_verified:
            raise AuthenticationFailed('Email is not Verified')
        return {
            'email': user.email,
            'id': user.id,
            'type': user.type,
            'tokens': user.tokens,
            # 'confirm_password' : user.confirm_password,

        }

        return super().validate(attrs),

    #
