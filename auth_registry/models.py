from uuid import uuid4
from django.db import models
from django.conf import settings
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin
)
import jwt
from datetime import datetime, timedelta


class UserManager(BaseUserManager):

    def create_user(self, email, phone, password=None):
        if email is None and phone is None:
            raise TypeError("User must have email or phone")
        
        user = self.model(email=self.normalize_email(email), phone=phone)
        user.set_password(password)
        user.save()

        return user

    def create_superuser(self, email, phone, password):

        if password is None:
            raise TypeError("SuperUser must have a password")

        user = self.create_user(email, phone, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()

        return user


class User(AbstractBaseUser, PermissionsMixin):
    id = models.IntegerField(primary_key=True)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=12)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    enabled = models.BooleanField(default=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["phone"]


    objects = UserManager()

    def __str__(self) -> str:
        return self.email

    @property
    def token(self):
        return self._generate_jwt_token()

    def get_full_name(self):
        return self.username

    def get_short_name(self):
        return self.username

    def _generate_jwt_token(self):
        dt = datetime.now() + timedelta(days=1)

        token = jwt.encode({
            'id': self.id,
            'exp': int(dt.strftime('%s'))
        }, settings.SECRET_KEY, algorithm="HS256")

        return token
