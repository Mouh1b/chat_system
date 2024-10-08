from django.http import JsonResponse
from django.shortcuts import render
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password

from rest_framework.authtoken.views import ObtainAuthToken
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.tokens import RefreshToken
from tuto.quickstart.permissions import CookieJWTAuthentication
from tuto.quickstart.serializers import MessagesSerializer, UserProfileSerializer
from rest_framework.exceptions import NotAuthenticated
from .models import Messages

User = get_user_model()

class RegisterView(APIView):
    def get(self, request):
        return render(request, 'register.html')
    
    def post(self, request):
        data = request.data
        password=data.get('password')
        if len(password)< 8:
            return Response({'error': 'Password must be at least 8 characters long'}, status=status.HTTP_400_BAD_REQUEST)
            
        if User.objects.filter(email=data['email']).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create(
            email=data['email'],
            first_name=data['first_name'],
            last_name=data['last_name'],
            password=make_password(data['password'])
        )
        response =Response({'message': 'User registered successfully'}, status=302)

        response['Location']="/login/"
        return response




class LoginView(ObtainAuthToken):
    def get(self, request):
        return render(request, 'login.html')
    
    def post(self, request, *args, **kwargs):
        user = authenticate(email=request.data.get('email'), password=request.data.get('password'))
        if user is not None:
            # Create JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)
            response = JsonResponse({
                'message': 'Login successful'
            },status=302
            )
            
            # Set the tokens in HttpOnly cookies
            response.set_cookie(
                key='access_token', 
                value=access_token, 
                secure=True,  # Set to True in production (for HTTPS)
                samesite='Lax'  # Adjust based on your needs (Lax, Strict, None)
            )
            response.set_cookie(
                key='refresh_token', 
                value=refresh_token, 
                secure=True,  
                samesite='Lax'
            )
            response['location']="/profile/"
            return response
        
        else:
            # If authentication fails, clear any existing access and refresh token cookies
            response = JsonResponse({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)
            response.delete_cookie('access_token')
            response.delete_cookie('refresh_token')
            return response



from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework.response import Response

class CookieTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        # Get the refresh token from cookies instead of the request body
        refresh_token = request.COOKIES.get('refresh_token')

        if refresh_token:
            request.data['refresh'] = refresh_token
            response = super().post(request, *args, **kwargs)

            if response.status_code == 200:
                # Get the new access token from the response
                access_token = response.data.get('access')

                # Set the new access token and refresh token in cookies
                response.set_cookie(
                    key='access_token',
                    value=access_token,
                    secure=True,    # Set this to True if using HTTPS
                    samesite='Lax'  # Adjust based on your security requirements
                )
                response.set_cookie(
                    key='refresh_token',
                    value=refresh_token,  # You can use a new refresh token if returned
                    secure=True,
                    samesite='Lax'
                )

            return response
        
    


class UserProfileView(APIView):
    serializer_class = UserProfileSerializer
    authentication_classes = [CookieJWTAuthentication] 

    def get(self, request):
     
        if not request.user.is_authenticated:
            raise NotAuthenticated('User is not authenticated')
        
        user = request.user
        user_info={
            "email": user.email,
            "name": user.first_name,
            "ln": user.last_name
        }
        print(user.email)
        return render(request, 'profile.html',context=user_info)
    

    
class Message(APIView):
    authentication_classes = [CookieJWTAuthentication] 
    serializer_class=MessagesSerializer

    def post(self,request):
        user=request.user
        data=request.data

        if data.get('message','')=='':
            return Response({'message': 'empty message'}, status=400)
        
        Messages.objects.create(
            author=user,
            message_content=data['message']
        )
        return Response({'message': 'message sent succesfully'}, status=201)
        
    def get(self,request):
        msg=Messages.objects.all()
        serializer=self.serializer_class(msg,many=True)
        return Response(serializer.data,status=200)
    
class Chat(APIView):
    def get(self,request):
        return render(request,'chat.html')