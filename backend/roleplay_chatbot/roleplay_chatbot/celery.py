# roleplay_chatbot/celery.py
from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'roleplay_chatbot.settings')

# Create a Celery instance and configure it with Django settings.
celery_app = Celery('roleplay_chatbot')

# Load task modules from all registered Django app configs.
celery_app.config_from_object('django.conf:settings', namespace='CELERY')

# Import tasks from each app
celery_app.autodiscover_tasks(['roleplay_manager'])  # Add more apps as needed
