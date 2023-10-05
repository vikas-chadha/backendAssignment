from rest_framework import serializers
from api.models import User
from api.models import Post
from django.core.exceptions import ValidationError
from BackendAssignment.settings import TIME12HRSFORMAT, DATEFORMAT


class UserLoginDetailSerializer(serializers.ModelSerializer):
    """
    Return the details of Login User.
    """

    class Meta(object):
        model = User
        fields = (
        'id', 'email', 'first_name', 'last_name', 'phone_no', 'is_active', 'is_deleted',)

class UserCreateUpdateSerializer(serializers.ModelSerializer):
    """
    create/update user .
    """

    class Meta:
        model = User
        fields = ('id', 'first_name','last_name', 'phone_no', 'email', 'password')
        extra_kwargs = {
            'password': {'write_only': True},
        }        

    def create(self, validated_data):
        user = User()
        user.first_name = validated_data['first_name']
        user.last_name = validated_data['last_name']
        user.phone_no = validated_data['phone_no']
        user.email = validated_data['email']
        user.set_password(validated_data['password'])
        user.is_active = True
        user.save()

        return user



class PostSerializer(serializers.ModelSerializer):
    """
    This is for update ,Create
    """
    class Meta(object):
        model = Post
        fields = ('__all__')


class PostDetailSerializer(serializers.ModelSerializer):
    """
    This is for Retrieving full data
    """
    user=UserLoginDetailSerializer()
    class Meta(object):
        model = Post
        fields = ('__all__')


