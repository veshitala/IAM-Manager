from __future__ import unicode_literals

from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    user = models.OneToOneField(User)
    access_key = models.CharField(max_length=500)
    secret_key = models.CharField(max_length=500)


class Policy(models.Model):
	arn = models.CharField(max_length=100)


class IAMUser(models.Model):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=100, unique=True)
    access_key = models.CharField(max_length=500, blank=True)
    secret_key = models.CharField(max_length=500, blank=True)
    password = models.CharField(max_length=500, null=True, blank=True)
    status = models.BooleanField(default=False)
    policies = models.ManyToManyField(Policy)
