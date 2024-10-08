from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed

class CookieJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # Extract the token from the cookies
        token = request.COOKIES.get('access_token')

        if not token:
            return None

        # Validate the token
        try:
            validated_token = self.get_validated_token(token)
        except AuthenticationFailed:
            return None
        
        # Retrieve the user from the validated token
        user = self.get_user(validated_token)

        # Return the authenticated user and the validated token
        return (user, validated_token)
