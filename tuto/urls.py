from django.urls import include, path
from django.contrib import admin
from tuto.quickstart.views import RegisterView, LoginView,UserProfileView,CookieTokenRefreshView,Message,Chat
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)


# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.
urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path ('admin/',admin.site.urls),
    path('profile/',UserProfileView.as_view(),name='profile'),
    path('api/token/refresh/', CookieTokenRefreshView.as_view(), name='token_refresh'),
    path('message/',Message.as_view(),name='message'),
    path('chat/',Chat.as_view(),name='chat'),
    
    
]