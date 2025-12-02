from rest_framework.decorators import api_view,permission_classes
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .serializers import RegisterSerializer,UserSerializer,UserEditSerializer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken


from django.core.signing import TimestampSigner,SignatureExpired,BadSignature
from django.urls import reverse
from django.core.mail import send_mail
from django.shortcuts import render,get_object_or_404
from .models import User
import re

from common import custom_permissions

def verification_email(request,user):
    signer = TimestampSigner()
    email_token = signer.sign(user.id)
    verify_url = request.build_absolute_uri(reverse("verify-email"))+f"?token={email_token}"
    message = f"hi {user} click here to verify your account on apostrophe {verify_url}"
    send_mail("vefify apostrophe account",message,'apsotrophe@email.com',[user.email])

@api_view(['POST'])
@permission_classes([AllowAny])
def registerView(request):
    serializer = RegisterSerializer(data = request.data)

    if serializer.is_valid() :
        user = serializer.save()

        verification_email(request,user)

        return Response({
            "message": "user has been created, verify your email","data":serializer.data
        })

    return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def loginView(request):
    username = request.data.get('username')
    password = request.data.get('password')

    if not username or not password:
        return Response({"error":"enter username and password"},status=status.HTTP_400_BAD_REQUEST)
    
    user = authenticate(username = username , password = password)

    if user is None:
        return Response({"error":"enter correct username and password"},status=status.HTTP_400_BAD_REQUEST)
    
    if not user.is_valid :
        verification_email(request,user)
        return Response({"error":"email is not verifcation, check the new email verification"},status=status.HTTP_400_BAD_REQUEST)

    token = RefreshToken.for_user(user)

    return Response({
        "message": "Login successful",
        "access": str(token.access_token),
        "refresh": str(token)
    }, status=200)


@api_view(["GET"])
@permission_classes([AllowAny])
def verifyEmailView(request):
    email_token = request.query_params.get("token")
    if not email_token:
        return Response({"error":"token not found!!!!"},status=status.HTTP_400_BAD_REQUEST)
    signer = TimestampSigner()
    try :
        user_id = signer.unsign(email_token,60)
    except SignatureExpired:
        return Response({"error":"token is expired"},status=status.HTTP_400_BAD_REQUEST)
    except BadSignature:
        return Response({"error":"invalid token"},status=status.HTTP_400_BAD_REQUEST)
    
    
    user = get_object_or_404(User,pk = user_id)
    user.is_valid = True
    user.save()
    return Response({"message":"email is verified "},status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
def resetPasswordRequest(request):
    email = request.data.get('email')
    if not email:
        return Response({"error":"enter email"},status=status.HTTP_400_BAD_REQUEST)
    if User.objects.filter(email = email).exists():
        user = get_object_or_404(User,email = email)
        signer = TimestampSigner()
        email_token = signer.sign(user.id)
        verify_url = request.build_absolute_uri(reverse("reset-password-verification"))+f"?token={email_token}"
        message = f"hi {user} , to reset your password click on the following url \n {verify_url}"
        send_mail("reset-password",message,"apostrophe@email.com",[user.email])
    return Response({
        "message":"email has been sent successfully"
        },status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([AllowAny])
def verfiyResetToken(request):
    email_token = request.query_params.get('token')
    if not email_token:
        return Response({
            "error":"token not found"
        },status=status.HTTP_400_BAD_REQUEST)
    signer = TimestampSigner()
    try :
        user_id = signer.unsign(email_token,60)

    except SignatureExpired:
        return Response({"error":"token expired"},status=status.HTTP_400_BAD_REQUEST)
    except BaseException:
        return Response({"error":"invalid token"},status=status.HTTP_400_BAD_REQUEST)
        
    return Response({"message":"token is valid","user_id":user_id},
                    status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
def resetPassword(request):
    email_token = request.data.get('token')
    password = request.data.get('password')
    password2 = request.data.get('password2')
    if not email_token or not password or not password2:
        return Response({"error":"toke and passwords are reuquired"},status=status.HTTP_400_BAD_REQUEST)
    signer = TimestampSigner()
    try:
        user_id = signer.unsign(email_token,60)

    except SignatureExpired:
        return Response({"error":"token expired"},status=status.HTTP_400_BAD_REQUEST)
    except BaseException:
        return Response({"error":"invalid token"},status=status.HTTP_400_BAD_REQUEST)

    user = get_object_or_404(User,id = user_id)
    if password != password2:
        return Response({"error":"password and password2 should be matched"},status=status.HTTP_400_BAD_REQUEST)
    if len(password) < 8 or len(password)>16:
        return Response({"error":"password should be at least 8 chars and at most 16 chars"},status=status.HTTP_400_BAD_REQUEST)
    if not re.search(r"[A-Z]",password):
        return Response({"error":"password should have at least one capital letter"},status=status.HTTP_400_BAD_REQUEST)
    if not re.search(r"[a-z]",password):
        return Response({"error":"password should have at least one small letter"},status=status.HTTP_400_BAD_REQUEST)
    if not re.search(r"[0-9]",password):
        return Response({"error":"password should have at least one number"},status=status.HTTP_400_BAD_REQUEST)
    user.set_password(password)
    user.save()
    return Response({"message":"passwrod reset succesfully "},status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([custom_permissions.IsManager])
def listUsers(request):
    users = User.objects.all()
    serializer = UserSerializer(users,many = True)
    return Response({"Users":serializer.data},status=status.HTTP_200_OK)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def editProfile(request):
    user = request.user
    serializer = UserEditSerializer(user,request.data,partial = True)
    if serializer.is_valid():
        serializer.save()
        print(serializer.data)
        return Response({"message":"successfully change first_name"},status=status.HTTP_200_OK)
    return Response({"error":serializer.errors},status=status.HTTP_400_BAD_REQUEST)