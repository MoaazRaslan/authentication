from rest_framework.decorators import api_view,permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from .serializers import RegisterSerializer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken


from django.core.signing import TimestampSigner,SignatureExpired,BadSignature
from django.urls import reverse
from django.core.mail import send_mail
from django.shortcuts import render,get_object_or_404
from .models import User

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
        user_id = signer.unsign(email_token,3)
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
def resetPassword(request):
    email = request.data.get('email')
    if not email:
        return Response({"error":"enter email"},status=status.HTTP_400_BAD_REQUEST)
    user = get_object_or_404(User,email = email)
    signer = TimestampSigner()
    email_token = signer.sign(user.id)
    verify_url = request.build_absolute_uri(reverse("reset-password"))+f"?token={email_token}"
    message = f"hi {user} , to reset your password click on the following url \n {verify_url}"
    send_mail("reset-password",message,"apostrophe@email.com",[user.email])
    return Response(
        {"message":"email has been sent successfully"},
        status=status.HTTP_200_OK
        )