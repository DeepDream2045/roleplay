# roleplay_chatbot/celery.py
from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'roleplay_chatbot.settings')

# Create a Celery instance and configure it with Django settings.
app = Celery('roleplay_chatbot')
# Load task modules from all registered Django app configs.
app.config_from_object('django.conf:settings', namespace='CELERY')
# Import tasks from each app
app.autodiscover_tasks() 

app.conf.update(
    task_time_limit=1800,  # Set task time limit to 1800 seconds (30 minutes)
    task_soft_time_limit=600,  # Set soft time limit to 600 seconds (10 minutes)
    worker_max_tasks_per_child=3600,  # Set maximum tasks per worker process
)