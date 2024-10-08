from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    def create_superuser(self, email, password=None, **extra_fields):
        
        user = self.create_user(
            email=self.normalize_email(email),
            password=password,
            
        )
        user.is_staff = True
        user.first_name=email
        user.last_name=email
        user.is_admin = True
        user.is_superuser = True
        user.save(using=self._db)
        return user
    
    
class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_admin  = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def __str__(self):
        return self.email
    def has_module_perm(self, app_label):
        return True
    def has_perm(self,perm,obj=None):
        return self.is_admin
    
    
class Messages(models.Model):
    message_id=models.AutoField(primary_key=True)
    creation_time=models.DateTimeField(default=timezone.now)
    author=models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    message_content=models.TextField(default='')
    
    def __str__(self):
        return self.message_content[:20]+"..." if len(self.message_content) > 20 else self.message_content
    
    class Meta: 
        ordering =('creation_time',)

        


