
from __future__ import unicode_literals
from django.db import models
from django.utils import timezone
from django.db import transaction
from django.contrib.auth.models import (
    AbstractBaseUser, PermissionsMixin, BaseUserManager
)

from django.conf import settings

class UserManager(BaseUserManager):

    def _create_user(self, email, password, **extra_fields):
        """
        Creates and saves a User with the given email,and password.
        """
        if not email:
            raise ValueError('The given email must be set')
        try:
            with transaction.atomic():
                user = self.model(email=email, **extra_fields)
                user.set_password(password)
                user.save(using=self._db)
                return user
        except:
            raise

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self._create_user(email, password=password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """
    An abstract base class implementing a fully featured User model with
    admin-compliant permissions.
 
    """
    # id = models.AutoField(primary_key=True)
    first_name = models.CharField(max_length=25, blank=True)
    middle_name = models.CharField(max_length=25, blank=True, null=True)
    last_name = models.CharField(max_length=25, blank=True)
    phone_no = models.CharField(max_length=17, help_text='Contact phone number')
    email = models.EmailField(max_length=254, blank=True, null=True, unique=True)
    password = models.CharField(max_length=254, blank=True, null=True)

    is_active = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(blank=True, null=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']


    def save(self, *args, **kwargs):
        super(User, self).save(*args, **kwargs)

    class Meta:
        db_table = 'auth_user'
        indexes = [
            models.Index(fields=['id', 'first_name', 'last_name', 'email', 'is_active'])
        ]

class UserSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.DO_NOTHING)
    device_id = models.CharField(max_length=100, null = True, blank= True)
    token = models.CharField(max_length=255, null = True, blank= True)
    device_type = models.CharField(max_length=20,  null = True, blank= True)
    app_version = models.CharField(max_length=60, null= True, blank= True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return str(self.user_id)

    class Meta:
        db_table = 'user_session'
        indexes = [
            models.Index(fields=['id'])
        ]

class Post(models.Model):
    user = models.ForeignKey(User, related_name="user_post", null=True, blank=True, on_delete=models.CASCADE)
    name = models.CharField(max_length=100, null = True, blank= True)
    title = models.CharField(max_length=255, null = True, blank= True)
    description = models.TextField(null = True, blank= True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return str(self.user_id)

    class Meta:
        db_table = 'post'
        indexes = [
            models.Index(fields=['id'])
        ]
        
