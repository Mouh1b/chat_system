from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from .models import Messages
User= get_user_model()

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','email', 'first_name', 'last_name']
        
class MessagesSerializer(serializers.ModelSerializer):
    class Meta:
        model=Messages
        fields= ['message_id','creation_time','author','message_content']

