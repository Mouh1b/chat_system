from django.contrib import admin
from .models import Messages,CustomUser

# Register your models here.
admin.site.register(Messages)
admin.site.register(CustomUser)