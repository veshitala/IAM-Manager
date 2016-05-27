from __future__ import unicode_literals

from django.db import models
from django.contrib.auth.models import User

REGIONS = (
    ('us-west-2', 'US West (Oregon)'),
    ('us-east-1', 'US East (N. Virginia)'),
    ('us-west-1', 'US West (N. California)'),
    ('eu-west-1', 'EU (Ireland)'),
    ('eu-central-1', 'EU (Frankfurt)'),
    ('ap-southeast-1', 'Asia Pacific (Singapore)'),
    ('ap-southeast-2', 'Asia Pacific (Sydney)'),
    ('ap-northeast-1', 'Asia Pacific (Tokyo)'),
    ('sa-east-1', 'South America (São Paulo)'),
)

