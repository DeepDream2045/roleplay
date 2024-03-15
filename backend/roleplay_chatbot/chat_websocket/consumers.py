import json
from rest_framework.response import Response
from asgiref.sync import async_to_sync
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.conf import settings
from roleplay_manager.models import *
from bot.pipeline import *
from lora_finetune.run_adapter import RunLoraAdapter
from datetime import datetime
import logging
from multiprocessing import Process, Manager

logger = logging.getLogger(__name__)


class ChatConsumer(AsyncWebsocketConsumer):
    """Class for chat conversion"""

    async def ___init__(self):
        """Constructor for initialize group id and room group name """

        self.user = None
        self.character = None
        self.model = None
        self.room_group_id = None
        self.chat = None
        self.is_adapter = False
        self.adapter = None
        return None

    async def connect(self):
        """Creating connection and Join room group"""

        try:
            self.is_adapter = False
            user_id = self.scope['url_route']['kwargs']['id']
            room_id = self.scope['url_route']['kwargs']['room_id']
            # try:
            #     self.is_adapter = self.scope['url_route']['kwargs']['is_adapter']
            # except Exception as error:
            #     pass
            flag = await database_sync_to_async(self.set_chat_room)(user_id, room_id)
            if flag:
                await self.channel_layer.group_add(
                    self.room_group_id,
                    self.channel_name,
                )
                await self.accept()
        except Exception as error:
            print("consumer connect error: ", error)
            logger.info(
                f"{datetime.now()} :: consumer connect user id- {self.user.id}")
            logger.info(
                f"{datetime.now()} :: consumer connect error :: {error}")
            Response(f"{error} error occurs")

    def set_chat_room(self, user_id, room_id):
        try:
            user = CustomUser.objects.filter(id=user_id)
            if user.exists():
                self.user = user.first()
                if self.is_adapter:
                    self.chat = AdapterChatRoom.objects.get(
                        user=self.user, room_id=room_id)
                    self.adapter = LoraModelInfo.objects.filter(
                        id=self.chat.adapter.id).first()
                else:
                    self.chat = ChatRoom.objects.get(
                        user=self.user, room_id=room_id)
                    self.character = CharacterInfo.objects.filter(
                        id=self.chat.character.id).first()
                    self.model = ModelInfo.objects.get(id=self.character.model_id.id)
                self.room_group_id = self.chat.room_id
                return True
        except Exception as error:
            print("consumer set_chat_room error: ", error)
            logger.info(
                f"{datetime.now()} :: consumer set_chat_room error :: {error} :: character id- {self.character.id}")
            Response(f"{error} error occurs")

    def set_character_info(self):
        try:
            custom_character_attribute = {}
            custom_character_attribute['charName'] = self.character.character_name
            custom_character_attribute['Short_Bio'] = self.character.short_bio
            custom_character_attribute["Gender"] = self.character.character_gender
            custom_character_attribute['initial_message'] = self.character.initial_message
            custom_character_attribute['character_story'] = self.character.character_story
            print(self.character.prompt)
            character_attribute_list = self.character.prompt.lower().strip().split(',\n')
            for i in character_attribute_list:
                custom_character_attribute[i.split(":")[0]] = i.split(":")[1]
            print(custom_character_attribute)
            model_info = {}
            model_info['model_id'] = self.model.huggingFace_model_name
            model_info['cache_dir'] = self.model.model_location
            model_info['prompt_template'] = self.model.prompt_template
            return custom_character_attribute, model_info
        except Exception as error:
            print("consumer set_character_info error: ", error)
            logger.info(
                f"{datetime.now()} :: consumer set_character_info user id- {self.user.id} :: character id- {self.character.id}\n{custom_character_attribute}")
            logger.info(
                f"{datetime.now()} :: consumer set_character_info error :: {error}")
            Response(f"{error} error occurs")

    def set_lora_adapter(self, lora_model, user_text):
        model_info = ModelInfo.objects.get(id=lora_model.base_model_id.id)
        run_lora_adapter_data = {
            'model_param': {
                'tokenizer': model_info.model_name,
                'base_model': model_info.model_name,
                'cache_dir': model_info.model_location,
                'token': settings.HF_TOKEN,
            },
            'adapter_path': lora_model.tuned_model_path,
            'text': user_text
        }
        return run_lora_adapter_data

    async def disconnect(self, close_code):
        """Reconnect after a delay (5 seconds)"""

        try:
            self.channel_layer.group_discard(
                self.room_group_id,
                self.channel_name
            )
        except Exception as error:
            print("consumer disconnect error: ", error)
            logger.info(
                f"{datetime.now()} :: consumer disconnect error :: {error}")
            Response(f"{error} error occurs")

    def run_llm_model(self, character_attribute, sender_user_message, model_info):
        manager = Manager()
        shared_list = manager.list()
        process = Process(target=start_model_llama2, args=(
            character_attribute, sender_user_message, model_info, shared_list))
        process.start()
        process.join()
        logger.info(shared_list)
        return shared_list

    async def receive(self, text_data):
        """Receive message from WebSocket and send to the group"""

        try:
            text_data_json = json.loads(text_data)
            sender_user_message = text_data_json['text']
            send_response_data, response = {}, {}

            if self.is_adapter:
                adapter_params = self.set_lora_adapter(
                    self.adapter, sender_user_message)
                adapter_message = RunLoraAdapter.run_adapter(
                    params=adapter_params)

                # response_instance = await self.create_msg(self.chat, sender_user_message)
                # response_instance.adapter_message = adapter_message
                # await database_sync_to_async(response_instance.save)()
                # send_response_data['message_id'] = response_instance.id

                send_response_data.update({
                    'type': 'chat_message',
                    'group_name': self.chat.get_group_name,
                    'sender_user_message': sender_user_message,
                    'adapter_message_message': adapter_message,

                    'sender_user_id': self.user.id,
                    'sender_name': self.user.full_name,
                    'sender_username': self.user.username,
                    'sender_profile_pic': self.sender_profile_pic,

                    'lora_adapter_id': self.adapter.id,
                    'lora_model_name': self.adapter.lora_model_name,
                })

            else:
                character_attribute, model_info = await database_sync_to_async(self.set_character_info)()
                # conversation = start_model_llama2(character_attribute)
                # response = conversation.invoke(sender_user_message)
                # character_message = response["response"].replace("\n\n", "\n")

                response = self.run_llm_model(character_attribute, sender_user_message, model_info)
                if response[1]:
                    character_message = response[0]["response"].replace("\n\n", " ")
                else:
                    character_message = response[0]

                if not self.user.is_guest:
                    response_instance = await self.create_msg(self.chat, sender_user_message)
                    response_instance.character_message = character_message
                    await database_sync_to_async(response_instance.save)()
                    send_response_data['message_id'] = response_instance.id

                self.sender_profile_pic = self.user.profile_image.url if self.user.profile_image else None
                self.character_profile_pic = self.character.image.url if self.character.image else None
                send_response_data.update({
                    'type': 'chat_message',
                    'group_name': self.chat.get_group_name,
                    'sender_user_message': sender_user_message,
                    'character_message': character_message,

                    'sender_user_id': self.user.id,
                    'sender_name': self.user.full_name,
                    'sender_username': self.user.username,
                    'sender_profile_pic': self.sender_profile_pic,

                    'character_id': self.character.id,
                    'character_name': self.character.character_name,
                    'character_profile_pic': self.character_profile_pic,
                })

            await (self.channel_layer.group_send)(
                self.room_group_id, send_response_data
            )
        except Exception as error:
            print("consumer receive error: ", error)
            if not self.is_adapter:
                logger.info(
                    f"{datetime.now()} :: consumer receive user id- {self.user.id} :: character id- {self.character.id}\n LLM Response:- {response}\n{character_attribute}")
            logger.info(
                f"{datetime.now()} :: consumer receive error :: {error}")
            Response(f"{error} error occurs")

    async def chat_message(self, event):
        """Receive message from room group and send to websocket"""

        try:
            print("CHAT RECEIVED")
            await self.send(text_data=json.dumps(event))
        except Exception as error:
            print("consumer chat_message error: ", error)
            logger.info(
                f"{datetime.now()} :: consumer chat_message error :: {error}")
            Response(f"{error} error occurs")

    @database_sync_to_async
    def create_msg(self, chatroom, user_msg):
        """Storing user chat data into database"""

        try:
            if user_msg is not None:
                if self.is_adapter:
                    chat_mag = AdapterChatMessage.objects.create(
                        chat=chatroom, user_message=user_msg)
                else:
                    chat_mag = ChatMessage.objects.create(
                        chat=chatroom, user_message=user_msg)
                chat_mag.save()
                print('created', chat_mag.id)
                return chat_mag
        except Exception as error:
            print("consumer create_msg error: ", error)
            logger.info(
                f"{datetime.now()} :: consumer create_msg error :: {error}")
            Response(f"{error} error occurs")
