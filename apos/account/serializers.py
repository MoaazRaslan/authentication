from rest_framework import serializers
from .models import User,Role
from django.contrib.auth.password_validation import validate_password


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only = True,validators = [validate_password])
    password2 = serializers.CharField(write_only = True)

    class Meta:
        model = User
        fields = ["username","email","password","password2"]
    
    def validate(self, attrs):
        if not attrs['password'] or attrs['password']!= attrs['password2']:
            raise serializers.ValidationError({"password":"password fields didn't match"})
    
        if User.objects.filter(email=attrs["email"]).exists():
            raise serializers.ValidationError({"message":"email is already exist"})
        return attrs
    
    def create(self,validated_data):
        validated_data.pop('password2')
        role = Role.objects.get(name = 'user')
        print(role) 
        user = User(
            username=validated_data["username"],
            email=validated_data["email"],
            role=role,
            is_valid=False
        )
        user.set_password(validated_data["password"])
        user.save()
        return user
    