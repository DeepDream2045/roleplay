from django.contrib import admin
from .models import (CustomUser, ChatRoom, ChatMessage, TokenRequest,
                      Tag, CharacterInfo, ModelInfo, Feedback)

# Register your models here.
class CustomUserAdmin(admin.ModelAdmin):
    """Create CustomUser admin for display on admin panel"""

    list_display = ('id','full_name', 'email')

class ChatMessageAdmin(admin.ModelAdmin):
    """Create ChatMessage admin for display on admin panel"""

    list_display=['id', 'chat', 'user_message', 'character_message']

class ChatRoomAdmin(admin.ModelAdmin):
    """Create ChatMessage admin for display on admin panel"""

    list_display=['id', 'room_id', 'type', 'group_name', 'user', 'character']

class TokenRequestAdmin(admin.ModelAdmin):
    """Create TokenRequest admin for display on admin panel"""

    list_display=['user','token', 'expiration_time']

class TagAdmin(admin.ModelAdmin):
    """Create Tag admin for display on admin panel"""

    list_display=['id', 'tag_name', 'user']

class CharacterInfoAdmin(admin.ModelAdmin):
    """Create CharacterInfo admin for display on admin panel"""

    list_display=['id','character_name', 'character_gender', 'display_tags']

    def display_tags(self, obj):
        return ", ".join([tag.name for tag in Tag.objects.all()])

    display_tags.short_description = 'Tags'

class ModelInfoAdmin(admin.ModelAdmin):
    """Create ModelInfo admin for display on admin panel"""

    list_display=['user_id','model_name']

class FeedbackAdmin(admin.ModelAdmin):
    """Create Feedback admin for display on admin panel"""

    list_display=['user_id','rating', 'review']

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(ChatRoom, ChatRoomAdmin)
admin.site.register(ChatMessage, ChatMessageAdmin)
admin.site.register(TokenRequest, TokenRequestAdmin)
admin.site.register(Tag, TagAdmin)
admin.site.register(CharacterInfo, CharacterInfoAdmin)
admin.site.register(ModelInfo, ModelInfoAdmin)
admin.site.register(Feedback, FeedbackAdmin)
