from django.db import models
from django.contrib.auth.models import User, AbstractUser, Group,Permission
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.conf import settings
from django.utils.translation import gettext as _
from django.utils import timezone


from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models

from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.utils.html import strip_tags
from django.template.loader import render_to_string


class Wilaya(models.Model):
    code = models.CharField(max_length=10)
    name = models.CharField(max_length=100)
    ar_name = models.CharField(max_length=100)
    longitude = models.CharField(max_length=50)
    latitude = models.CharField(max_length=50)

    def __str__(self):
        return self.name

class City(models.Model):
    post_code = models.CharField(max_length=10)
    name = models.CharField(max_length=100)
    wilaya = models.ForeignKey(Wilaya, on_delete=models.CASCADE)
    ar_name = models.CharField(max_length=100)
    longitude = models.CharField(max_length=50)
    latitude = models.CharField(max_length=50)

    def __str__(self):
        return self.name


class Client(models.Model):
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=15)
    password = models.CharField(max_length=128)
    name = models.CharField(max_length=30, null=True, blank=True)
    last_name = models.CharField(max_length=30, null=True, blank=True)
    birth_date = models.DateField(null=True, blank=True)
    wilaya = models.ForeignKey(Wilaya, on_delete=models.CASCADE)
    city = models.ForeignKey(City, on_delete=models.CASCADE)
    id_number = models.CharField(max_length=50, unique=True, null=True, blank=True)
   
    def __str__(self):
        return self.name + " "+self.last_name
    # USERNAME_FIELD = 'email'
   



