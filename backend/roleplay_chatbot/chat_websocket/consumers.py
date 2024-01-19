import json
from rest_framework.response import Response
from asgiref.sync import async_to_sync
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from roleplay_manager.models import CustomUser, ChatRoom, ChatMessage, CharacterInfo
from bot.pipeline import *


class ChatConsumer(AsyncWebsocketConsumer):
    """Class for chat conversion"""

    async def ___init__(self):
        """Constructor for initialize group id and room group name """

        self.user = None
        self.chsracter = None
        self.room_group_id =None
        self.chat = None

    async def connect(self):
        """Creating connection and Join room group"""

        user_id = self.scope['url_route']['kwargs']['id']
        character_id = self.scope['url_route']['kwargs']['character_id']
        flag = await database_sync_to_async(self.set_chat_room)(user_id, character_id)
        if flag:
            character_attribute = await database_sync_to_async(self.set_character_info)()
            self.conversation = start_model_llama2(character_attribute)
            await self.channel_layer.group_add(
                self.room_group_id,
                self.channel_name,
            )
            await self.accept()

    def set_chat_room(self, user_id, character_id):
        try:
            user = CustomUser.objects.filter(id=user_id)
            if user.exists():
                self.user = user.first()
                self.character = CharacterInfo.objects.filter(id=character_id).first()
                self.chat, created = ChatRoom.objects.get_or_create(user = self.user, character = self.character)
                self.room_group_id = self.chat.room_id
                if self.chat.group_name is None:
                    self.chat.group_name = self.chat.get_group_name
                    self.chat.save()
                return True
        except Exception as error:
            print(error)
            Response(f"{error} error occurs")

    def set_character_info(self):
        custom_character_attribute = {}
        custom_character_attribute['charName'] = self.character.character_name
        custom_character_attribute['Short_Bio'] = self.character.short_bio
        custom_character_attribute["Gender"] = self.character.character_gender
        custom_character_attribute['initial_message'] = self.character.initial_message
        character_attribute_list = self.character.prompt.lower().strip().split('\n')
        for i in character_attribute_list:
            custom_character_attribute[i.split(":")[0]] = i.split(":")[1]
        print(custom_character_attribute)
        return custom_character_attribute

    async def disconnect(self, close_code):
        """Reconnect after a delay (5 seconds)"""
        # await self.connect()
        # Leave room group
        self.channel_layer.group_discard(
            self.room_group_id,
            self.channel_name
        )

    async def receive(self, text_data):
        """Receive message from WebSocket and send to the group"""
        
        text_data_json = json.loads(text_data)
        sender_user_message = text_data_json['text']

        response_instance = await self.create_msg(self.chat, sender_user_message)

        response = self.conversation.invoke(sender_user_message)
        character_message = response["response"].replace("\n\n", "\n")

        self.sender_profile_pic = self.user.profile_image.url if self.user.profile_image else None
        self.character_profile_pic = self.character.image.url if self.character.image else None

        await (self.channel_layer.group_send)(
            self.room_group_id,
            {
                'type': 'chat_message',
                'message_id':response_instance.id,
                'group_name':self.chat.get_group_name,
                'sender_user_message': sender_user_message,
                'character_message': character_message,

                'sender_user_id': self.user.id,
                'sender_email': self.user.email,
                'sender_profile_pic': self.sender_profile_pic,

                'character_id': self.character.id,
                'character_name': self.character.character_name,
                'character_profile_pic': self.character_profile_pic,
            }
        )

    async def chat_message(self, event):
        """Receive message from room group and send to websocket"""

        print("CHAT RECEIEVED")
        await self.send(text_data=json.dumps({
            'message_id':event['message_id'],
            'sender_user_message': event['sender_user_message'],
            'character_message': event['character_message'],

            'sender_user_id': event['sender_user_id'],
            'sender_email': event['sender_email'],
            'sender_profile_pic': event['sender_profile_pic'],

            'character_id': event['character_id'],
            'character_name': event['character_name'],
            'character_profile_pic': event['character_profile_pic'],
        }))

    @database_sync_to_async
    def create_msg(self, chatroom, user_msg):
        """Storing user chat data into database"""

        try:
            if user_msg is not None:
                chat_mag = ChatMessage.objects.create(chat=chatroom, user_message=user_msg)
                chat_mag.save()
                print('created', chat_mag.id)
                return chat_mag
        except Exception as e:
            Response(f"{e} error occurs")


