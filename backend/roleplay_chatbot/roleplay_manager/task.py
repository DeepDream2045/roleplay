from celery import shared_task, chain
from roleplay_manager import celery_app
from .models import *
import logging
import random
from datetime import datetime
import json
from django.conf import settings
import os
from lora_finetune.fine_tune_llama2 import FineTuneLLMLora

logger = logging.getLogger(__name__)


@shared_task
def fetch_lora_modal_data(user_id, lora_model_id):
    try:
        user = CustomUser.objects.get(id=user_id)
        lora_model = LoraModelInfo.objects.get(id=lora_model_id)
        logger.debug(f"{datetime.now()} :: lora_model: {lora_model}")
        model_info = ModelInfo.objects.get(id=lora_model.base_model_id.id)
        # print(lora_model.dataset)
        dataset_dict = json.loads(lora_model.dataset)
        # print("DataType:", type(dataset_dict))
        """ create entry for lora adapter in LoraTrainingStatus table """
        # Create or update LoraTrainingStatus entry with status 'running'
        training_status_instance, created = LoraTrainingStatus.objects.get_or_create(
            user=user,
            lora_model_info=lora_model,
            defaults={'current_status': 'running'}
        )
        # If the entry already existed, update the status to 'running'
        if not created:
            training_status_instance.current_status = 'running'
            training_status_instance.save()

        """Data format"""
        lora_modal_data = {
            'run_lora_param': {
                'tokenizer': model_info.model_name,
                'base_model': model_info.model_name,
                'cache_dir': model_info.model_location,
                'token': settings.HF_TOKEN,
            },
            'set_training_arguments_param': {
                'adapter_output_dir': lora_model.tuned_model_path,
                'num_train_epochs': lora_model.num_train_epochs,
                'per_device_train_batch_size': lora_model.per_device_train_batch_size,
                'learning_rate': lora_model.learning_rate,
                'warmup_steps': lora_model.warmup_steps,
                'optim': lora_model.optimizer,
                'lr_scheduler_type': lora_model.lr_scheduler_type,
                'gradient_accumulation_steps': lora_model.gradient_accumulation_steps,
            },
            'config_lora_param': {
                'alpha': lora_model.lora_alpha,
                'dropout': lora_model.lora_dropout,
                'r': lora_model.lora_r,
                'bias': lora_model.lora_bias,
            },

            'dataset': dataset_dict
        }
        process_lora_modal_data.delay(
            lora_modal_data, lora_model_id, user.id, training_status_instance.current_status)

    except LoraModelInfo.DoesNotExist:
        logger.error(
            f"{datetime.now()} :: Lora Model with ID {lora_model_id} does not exist.")
    except ModelInfo.DoesNotExist:
        logger.error(
            f"{datetime.now()} :: ModelInfo related to Lora Model {lora_model_id} does not exist.")
    except Exception as e:
        logger.exception(
            f"{datetime.now()} :: An unexpected error occurred: {e}")
        return {'status': 'error', 'message': f"{datetime.now()} :: An unexpected error occurred: {e}"}


# second task to train lora adapters =============================
@shared_task
def process_lora_modal_data(lora_modal_data, lora_model_id, user_id, current_status):
    try:
        """
        code for llm training status failed or success
        """
        check_training_status = FineTuneLLMLora().run_lora(lora_modal_data)
        # check_training_status = 'completed'

        if check_training_status:
            # Update LoraTrainingStatus to 'completed'
            update_lora_training_status(
                user_id, lora_model_id, 'completed', 'no error found')
            return check_training_status
        else:
            update_lora_training_status(
                user_id, lora_model_id, 'error', 'found error')
            return 'error'

    except Exception as e:
        logger.exception(
            f"{datetime.now()} :: An unexpected error occurred during processing: {e}")
        update_lora_training_status(
            user_id, lora_model_id, 'error', 'found error')
        return 'error'


# Helper function to update LoraTrainingStatus
def update_lora_training_status(user_id, lora_model_id, status, error=None):
    try:
        lora_training_status_instance = LoraTrainingStatus.objects.get(
            user_id=user_id,
            lora_model_info_id=lora_model_id
        )
        lora_training_status_instance.current_status = status
        if error:
            lora_training_status_instance.lora_training_error = error
        lora_training_status_instance.save()
    except LoraTrainingStatus.DoesNotExist:
        logger.error(
            f"{datetime.now()} :: Lora Training Status does not exist for user {user_id} and model {lora_model_id}")
    except Exception as e:
        logger.exception(
            f"{datetime.now()} :: An unexpected error occurred during Lora Training Status update: {e}")
