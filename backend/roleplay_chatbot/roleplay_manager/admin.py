from django.contrib import admin

from .models import CustomUser, ChatMessage

# Register your models here.


class CustomUserAdmin(admin.ModelAdmin):
    """Create CustomUser admin for display on admin panel"""

    list_display = ('full_name', 'email')

class ChatMessageAdmin(admin.ModelAdmin):
    """Create subscriber admin for display on admin panel"""

    list_display=['id','sender', 'receiver']

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(ChatMessage, ChatMessageAdmin)