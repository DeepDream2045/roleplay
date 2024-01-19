from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from django.urls import re_path
from channels.auth import AuthMiddlewareStack
from .consumers import ChatConsumer

websocket_urlpatterns = [
    re_path(r'asw/(?P<id>\w+)/(?P<character_id>\w+)', ChatConsumer.as_asgi()),   
]
