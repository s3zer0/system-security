from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin

admin.site.unregister(User)

class CustomUserAdmin(UserAdmin):
    list_display = (
        'username', 
        'email', 
        'first_name',
        'is_staff'
    )

admin.site.register(User, CustomUserAdmin)