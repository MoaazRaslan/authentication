from django.db import models
from django.contrib.auth.models import AbstractUser

class Role(models.Model):
    ROLES_CHOICES = (
        ('user','User'),
        ('manager','Manager'),
        ('admin','Admin'),
    )
    
    name = models.CharField(choices=ROLES_CHOICES)

    def __str__(self):
        return self.name
    
class User(AbstractUser):
    role = models.ForeignKey(Role,on_delete=models.CASCADE,null=True)
    is_valid = models.BooleanField(default=False)

    def __str__(self):
        return self.username