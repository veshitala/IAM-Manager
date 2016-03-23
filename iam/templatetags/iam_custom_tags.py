from django import template
from iam.models import *

register = template.Library()


@register.filter
def get_iam_user(username):
    user = IAMUser.objects.filter(username=username)
    return user
