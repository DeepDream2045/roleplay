from django.contrib import admin
from .models import *

# Register your models here.


class CustomUserAdmin(admin.ModelAdmin):
    """Create CustomUser admin for display on admin panel"""

    list_display = ('id', 'full_name', 'username', 'email', 'provider')


class ChatMessageAdmin(admin.ModelAdmin):
    """Create ChatMessage admin for display on admin panel"""

    list_display = ['id', 'chat', 'user_message', 'character_message']


class ChatRoomAdmin(admin.ModelAdmin):
    """Create ChatMessage admin for display on admin panel"""

    list_display = ['id', 'room_id', 'type', 'group_name', 'user', 'character']


class TokenRequestAdmin(admin.ModelAdmin):
    """Create TokenRequest admin for display on admin panel"""

    list_display = ['user', 'token', 'expiration_time']


class TagAdmin(admin.ModelAdmin):
    """Create Tag admin for display on admin panel"""

    list_display = ['id', 'tag_name', 'user']


class CharacterInfoAdmin(admin.ModelAdmin):
    """Create CharacterInfo admin for display on admin panel"""

    list_display = ['id', 'character_name',
                    'character_gender', 'display_tags', 'user']

    def display_tags(self, obj):
        return ", ".join([tag.tag_name for tag in obj.tags.all()])

    display_tags.short_description = 'Tags'


class ModelInfoAdmin(admin.ModelAdmin):
    """Create ModelInfo admin for display on admin panel"""

    list_display = ['id', 'user', 'model_name', 'short_bio', 'model_location']


class FeedbackAdmin(admin.ModelAdmin):
    """Create Feedback admin for display on admin panel"""

    list_display = ['user', 'types', 'content']


class LoraModelValuesAdmin(admin.ModelAdmin):
    list_display = ['id', 'lora_model_name', 'user', 'lora_short_bio',
                    'base_model_id', 'tuned_model_path']


class LoraTrainingStatusAdmin(admin.ModelAdmin):
    list_display = ['id', 'lora_model_info', 'user', 'current_status',
                    'lora_training_error']


class AdapterChatRoomAdmin(admin.ModelAdmin):
    """Create Adapter chat room info for display on admin panel"""

    list_display = ['id', 'adapter_room_id',
                    'type', 'group_name', 'user', 'adapter']


class AdapterChatMessageAdmin(admin.ModelAdmin):
    """Create Adapter ChatMessage for display on admin panel"""

    list_display = ['id', 'adapter_chatroom',
                    'user_message', 'adapter_message']


class MetaMaskTransactionHistoryAdmin(admin.ModelAdmin):
    """Create MetaMaskTransactionHistory for display on admin panel"""

    list_display = ['id', 'sender',
                    'receiver', 'amount', 'status', 'transaction_hash']


class UserCaptchaAdmin(admin.ModelAdmin):
    """Create MetaMask get captcha for display on admin panel"""

    list_display = ['id', 'captcha', 'user']


admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(ChatRoom, ChatRoomAdmin)
admin.site.register(ChatMessage, ChatMessageAdmin)
admin.site.register(TokenRequest, TokenRequestAdmin)
admin.site.register(Tag, TagAdmin)
admin.site.register(CharacterInfo, CharacterInfoAdmin)
admin.site.register(ModelInfo, ModelInfoAdmin)
admin.site.register(Feedback, FeedbackAdmin)
admin.site.register(LoraModelInfo, LoraModelValuesAdmin)
admin.site.register(LoraTrainingStatus, LoraTrainingStatusAdmin)
admin.site.register(AdapterChatRoom, AdapterChatRoomAdmin)
admin.site.register(AdapterChatMessage, AdapterChatMessageAdmin)
admin.site.register(MetaMaskTransactionHistory,
                    MetaMaskTransactionHistoryAdmin)
admin.site.register(UserCaptcha, UserCaptchaAdmin)
