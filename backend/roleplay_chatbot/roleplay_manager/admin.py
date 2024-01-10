from django.contrib import admin
from .models import (CustomUser, ChatMessage, TokenRequest,
                      Tag, CharacterInfo, ModelInfo, Feedback)

# Register your models here.
class CustomUserAdmin(admin.ModelAdmin):
    """Create CustomUser admin for display on admin panel"""

    list_display = ('full_name', 'email')

class ChatMessageAdmin(admin.ModelAdmin):
    """Create ChatMessage admin for display on admin panel"""

    list_display=['id','sender', 'receiver']

class TokenRequestAdmin(admin.ModelAdmin):
    """Create TokenRequest admin for display on admin panel"""

    list_display=['user','token', 'expiration_time']

class TagAdmin(admin.ModelAdmin):
    """Create Tag admin for display on admin panel"""

    list_display=['tag_id','tag_name', 'user_added_by']

class CharacterInfoAdmin(admin.ModelAdmin):
    """Create CharacterInfo admin for display on admin panel"""

    list_display=['id','character_name', 'character_gender', 'tag_id']

class ModelInfoAdmin(admin.ModelAdmin):
    """Create ModelInfo admin for display on admin panel"""

    list_display=['user_id','model_name']

class FeedbackAdmin(admin.ModelAdmin):
    """Create Feedback admin for display on admin panel"""

    list_display=['user_id','rating', 'review']

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(ChatMessage, ChatMessageAdmin)
admin.site.register(TokenRequest, TokenRequestAdmin)
admin.site.register(Tag, TagAdmin)
admin.site.register(CharacterInfo, CharacterInfoAdmin)
admin.site.register(ModelInfo, ModelInfoAdmin)
admin.site.register(Feedback, FeedbackAdmin)
