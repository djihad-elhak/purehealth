from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.sessions.models import Session
from django.core.mail import send_mail, EmailMultiAlternatives, BadHeaderError
from django.db import models
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from jwt import decode
from jwt.exceptions import DecodeError, ExpiredSignatureError
from rest_framework import generics, status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
import datetime
import json
import random
from .authenticated import JWTAuthentication
from .models import Client
from .serializers import PasswordResetRequestSerializer, PasswordResetSerializer, UserSerializer, ChangePassword
from .serializers import  OTPSerializer, PersonalInfoSerializer, UploadFileSerializer
import random
import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import User,Wilaya,City
from .serializers import  OTPSerializer, PersonalInfoSerializer, UploadFileSerializer
import random
import requests

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.core.exceptions import ObjectDoesNotExist
from .serializers import (
    RegisterSerializer, PersonalInfoSerializer,
    IdCardSerializer
)
def generate_otp():
    return ''.join(random.choices('0123456789', k=6))


def send_otp(email, otp):
    subject = 'Your OTP Code'
    message = f'Your OTP code is {otp}'
    email_from = settings.DEFAULT_FROM_EMAIL
    recipient_list = [email]

    send_mail(subject, message, email_from, recipient_list)


# views.py
class RegisterStep1View(APIView):
    serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            phone = serializer.validated_data['phone']
            password = serializer.validated_data['password']

            if Client.objects.filter(email=email).exists():
                return Response({"error": "Email is already in use"}, status=status.HTTP_400_BAD_REQUEST)
            if Client.objects.filter(phone=phone).exists():
                return Response({"error": "Phone number is already in use"}, status=status.HTTP_400_BAD_REQUEST)

            # Store in session
            request.session['step1'] = {'email': email, 'phone': phone, 'password': password}

            otp = generate_otp()
            request.session['otp'] = otp
            send_otp(email, otp)
            
            return Response({"message": "OTP sent to email"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            



class VerifyOTPView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = OTPSerializer(data=request.data)
        if serializer.is_valid():
            otp = serializer.validated_data['otp']
            stored_otp = request.session.get('otp')

            if not stored_otp:
                return Response({"error": "OTP not found or expired"}, status=status.HTTP_400_BAD_REQUEST)

            if otp == stored_otp:
                request.session['otp_verified'] = True
                return Response({"message": "OTP verified successfully"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class RegisterStep3View(APIView):
    serializer_class = PersonalInfoSerializer

    def post(self, request, *args, **kwargs):
        if not request.session.get('otp_verified'):
            return Response({"error": "OTP verification is required"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = PersonalInfoSerializer(data=request.data)
        if serializer.is_valid():
            print(serializer)
            personal_info = serializer.validated_data
            print(personal_info)
            personal_info['birth_date'] = personal_info['birth_date'].isoformat()
            personal_info['wilaya'] = personal_info['wilaya'].id
            personal_info['city'] = personal_info['city'].id
            # Store personal information in session
            request.session['step3'] = personal_info
            request.session.save()  # Ensure session is saved



            # Store personal information in session


            return Response({"message": personal_info}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



def ocr_space_api(file_path, overlay=False, api_key='YOUR_API_KEY', language='eng'):
    payload = {
        'isOverlayRequired': overlay,
        'apikey': api_key,
        'language': language,
        'OCREngine' : 2,
    }
    with open(file_path, 'rb') as f:
        r = requests.post('https://api.ocr.space/parse/image',
                          files={file_path: f},
                          data=payload,
                          )
    return r.json()



























# users/views.py

# Additional code here

# users/views.py

# Additional code here

# Create your views here.
@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])

def change_password(request):
  if request.method == 'POST':
        serializer = ChangePassword(data=request.data)
        if serializer.is_valid():
              user = request.user
              if user.check_password(serializer.data.get('old_password')):
                    user.set_password(serializer.data.get('new_password'))
                    user.save()
                    return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
              return Response({'error': 'Incorrect old password.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
 #Create your views here.
# views.py
# views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .forms import UploadFileForm
import requests
import os
import re


from datetime import datetime

def format_birthdate(birthdate_str):
    """
    Formats a birthdate from YYMMDD to YYYY-MM-DD.
    """
    return datetime.strptime(birthdate_str, '%y%m%d').strftime('%Y-%m-%d')

def extract_details(parsed_text):
    """
    Extracts the name, last name, birthdate, and ID number from the OCR parsed text.
    """
    name_pattern = r'Prénom\(s\):\s*([\w\s]+)'
    last_name_pattern = r'Nom:\s*(\w+)'
    birthdate_pattern = r'(\d{6})2M'
    id_number_pattern = r'IDDZA(\d+)'

    name_match = re.search(name_pattern, parsed_text)
    last_name_match = re.search(last_name_pattern, parsed_text)
    birthdate_match = re.search(birthdate_pattern, parsed_text)
    id_number_match = re.search(id_number_pattern, parsed_text)

    name = name_match.group(1).strip().split('\n')[0] if name_match else ''
    last_name = last_name_match.group(1).strip() if last_name_match else ''
    birthdate = format_birthdate(birthdate_match.group(1)) if birthdate_match else ''
    id_number = id_number_match.group(1) if id_number_match else ''

    return {
        'name': name,
        'last_name': last_name,
        'birth_date': birthdate,
        'id_number': id_number
    }
def extract_data_from_ocr(result):
    parsed_text = result['ParsedResults'][0]['ParsedText']
    
    name_line = parsed_text.split('Prénom(s): ')[1].split('\n')[0].strip()
    name = name_line.split('<')[0].replace('<', ' ').strip()
    
    last_name_line = parsed_text.split('Nom: ')[1].split('\n')[0].strip()
    last_name = last_name_line.split('<')[0].replace('<', ' ').strip()
    
    birthdate_raw = parsed_text.split('041229')[1].split('<')[0]
    birthdate = datetime.datetime.strptime(birthdate_raw, '%y%m%d').date()

    id_number = parsed_text.split('IDD')[1].split('<<<<')[0]

    return {
        'name': name,
        'last_name': last_name,
        'birth_date': birthdate,
        'id_number': id_number
    }

class RegisterStep4View(APIView):
    def post(self, request, *args, **kwargs):
        
        form = UploadFileForm(request.POST, request.FILES)
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['file']
            file_name = file.name
            file_path = os.path.join(os.path.dirname(__file__), 'uploads', file_name)
            
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'wb+') as destination:
                for chunk in file.chunks():
                    destination.write(chunk)
            result = ocr_space_api(file_path, api_key='K87236353188957')
            print("hello\n")

        
            parsed_text = result.get('ParsedResults', [{}])[0].get('ParsedText', '')
            ocr_data = extract_details(parsed_text)
            print("hello\n")


            personal_info = request.session['step3']
            print("hello\n")
            print(personal_info)
            if (ocr_data['name'] == personal_info['name'] and
                ocr_data['last_name'] == personal_info['last_name'] and
                ocr_data['birth_date'] == personal_info['birth_date']):
                
                # Check if the ID number is unique
                if Client.objects.filter(id_number=ocr_data['id_number']).exists():
                    return Response({"error": "ID number is already in use"}, status=status.HTTP_400_BAD_REQUEST)
                

                if 'step1' not in request.session:
                    return Response({"error": "Step 1 data is missing in session"}, status=status.HTTP_400_BAD_REQUEST)

                if not personal_info:
                    return Response({"error": "Personal info data is missing"}, status=status.HTTP_400_BAD_REQUEST)

# Retrieve the primary key values for wilaya and city from personal_info
                wilaya_id = personal_info.pop('wilaya', None)
                city_id = personal_info.pop('city', None)

# Check if wilaya_id and city_id are valid
                if wilaya_id is None or city_id is None:
                    return Response({"error": "Wilaya or City ID is missing"}, status=status.HTTP_400_BAD_REQUEST)

# Get the Wilaya and City instances
                try:
                    wilaya_instance = Wilaya.objects.get(id=wilaya_id)
                    city_instance = City.objects.get(id=city_id)
                except Wilaya.DoesNotExist:
                    return Response({"error": "Wilaya not found"}, status=status.HTTP_404_NOT_FOUND)
                except City.DoesNotExist:
                    return Response({"error": "City not found"}, status=status.HTTP_404_NOT_FOUND)

                # Combine session data and personal_info with the Wilaya and City instances
                user_data = {**request.session['step1'], **personal_info, 'id_number': ocr_data.get('id_number')}
                user_data['wilaya'] = wilaya_instance
                user_data['city'] = city_instance

                # Create the Client instance
                Client.objects.create(**user_data)

                # Return a success response
                return Response({"message": "Client created successfully"}, status=status.HTTP_201_CREATED)




















                
@csrf_exempt
def upload_file(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['file']
            file_name = file.name
            file_path = os.path.join(os.path.dirname(__file__), 'uploads', file_name)
            
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'wb+') as destination:
                for chunk in file.chunks():
                    destination.write(chunk)
            result = ocr_space_api(file_path, api_key='K87236353188957')
            
            parsed_text = result.get('ParsedResults', [{}])[0].get('ParsedText', '')
            extracted_details = extract_details(parsed_text)

            response_data = {
                **extracted_details,
            }
            return JsonResponse(response_data)
    return JsonResponse({'error': 'Invalid request method'}, status=405)




class PasswordResetRequestView(APIView):
   
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = Client.objects.get(email=email)
                token_value = generate_token()
                token = PasswordResetToken.objects.create(user=user,token=token_value)
               
                # Send email
                try:
                    
                    send_mail(
                          'Password Reset Request',
                         f'Use the following token to reset your password: {token.token}',
                         settings.DEFAULT_FROM_EMAIL,
                         [email],
                        
                    )
                    return Response({'message': 'Password reset link has been sent to your email.'}, status=status.HTTP_200_OK)
                except BadHeaderError:
                    return Response({'error': 'Invalid header found.'}, status=status.HTTP_400_BAD_REQUEST)
                except Exception as e:
                    return Response({'error': f'Failed to send email. {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            except Client.DoesNotExist:
                return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetView(APIView):
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            new_password = serializer.validated_data['new_password']
            try:
                reset_token = PasswordResetToken.objects.get(token=token, expires_at__gte=timezone.now())
                user = reset_token.user
                user.set_password(new_password)
                user.save()
                reset_token.delete()  # Invalidate the token
                return Response({'message': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
            except PasswordResetToken.DoesNotExist:
                return Response({'error': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RegisterAPIView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data) 
       
        if serializer.is_valid(): 
            
                    
            serializer.save()  #
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    # def get(self, request):
        # users = User.objects.all()
        # # serializer = UserSerializer(users, many=True)
        # return Response(serializer.data)

class LoginAPIView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        
        user_queryset = Client.objects.filter(username=username)
         
        if not user_queryset.exists():
            raise AuthenticationFailed('User not found')
    
        user = user_queryset.first()
        
        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password') 
        payload ={
          'id': user.id,
          'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=600),
          'iat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256')
        response = Response()
        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {'jwt': token}
        
        return response
    
    class LogoutView(APIView):
        def post(self, request):
            response =Response()
            response.delete_cookie('jwt')
            response.data = {
                'message' :'success'
            }
            return response

