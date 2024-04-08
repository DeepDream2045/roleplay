from datasets import Dataset
import os
import pandas as pd
from peft import PeftModel
import time
import torch
from transformers import BitsAndBytesConfig, TrainingArguments
# from multiprocessing import Process, Manager
from billiard import Process, Manager
try:
    from .base_lora import LoraModel, release_memory
    from .gpu_allocation import get_GPU_Info
except:
    from .base_lora import LoraModel, release_memory
    from .gpu_allocation import get_GPU_Info


def validate_folder(folder_path):
    """
    Check if specific files are present in the folder.

    Args:
        folder_path (str): The path to the folder.
        filenames (list): A list of filenames to check for.

    Returns:
        dict: A dictionary indicating whether each file is present or not.
    """

    files_present = {}
    filenames = ['adapter_config.json', 'adapter_model.safetensors']
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            for filename in filenames:
                if filename == file:
                    files_present[filename] = True
    if len(files_present.values()) == 2:
        return True
    return False


class FineTuneLLMLora:
    def prepare_llava_dataset(dataset, output_folder):
        # Initialize list to hold all JSON data
        json_data_list = []

        # Process each item in the dataset
        for item in dataset:
            # Create a unique ID for each example
            unique_id = str(uuid.uuid4())

            # Get the image filename and URL
            image_url = item["image"]
            image_filename = f"{unique_id}.jpg"

            # Download and save the image
            response = requests.get(image_url)
            image_path = os.path.join(output_folder, 'images', image_filename)
            if not os.path.exists(os.path.dirname(image_path)):
                os.makedirs(os.path.dirname(image_path))
            with open(image_path, 'wb') as image_file:
                image_file.write(response.content)

            # Remove duplicates and format answers
            answers = item['answers']
            unique_answers = list(set(answers))
            formatted_answers = ", ".join(unique_answers)

            # Structure for LLaVA JSON
            json_data = {
                "id": unique_id,
                "image": image_filename,
                "conversations": [
                    {
                        "from": "human",
                        "value": item['question']
                    },
                    {
                        "from": "gpt",
                        "value": formatted_answers
                    }
                ]
            }

            # Append to list
            json_data_list.append(json_data)

        # Return the data in the Dataset format similar to HuggingFace's 'datasets'
        return Dataset.from_dict({'data': json_data_list})

    def create_quant_config(self):
        return BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type='nf4',
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=False
        )

    def init_adaptor_model(self, params, gpu_list):
        adaptor = LoraModel()
        adaptor.init_tokenizer(
            params['tokenizer'], cache_dir=params['cache_dir'], token=params['token'])
        adaptor.init_base_model(params['base_model'], self.create_quant_config(
        ), cache_dir=params['cache_dir'], token=params['token'], gpu_list=gpu_list)
        return adaptor

    def set_training_arguments(self, adaptor, params):
        adaptor.training_params = TrainingArguments(
            output_dir=params['adapter_output_dir'],
            num_train_epochs=params.get('num_train_epochs', 1),
            per_device_train_batch_size=params.get(
                'per_device_train_batch_size', 1),
            learning_rate=params.get('learning_rate', 0.0002),
            warmup_steps=params.get('warmup_steps', 0),
            optim=params.get('optim', 'paged_adamw_8bit'),
            lr_scheduler_type=params.get('lr_scheduler_type', 'constant'),
            gradient_accumulation_steps=params.get(
                'gradient_accumulation_steps', 1),
            save_steps=25,
            logging_steps=25,
            weight_decay=0.001,
            fp16=True,
            bf16=False,
            max_grad_norm=0.3,
            max_steps=-1,
            remove_unused_columns=False
        )

    def config_lora(self, adaptor, params):
        adaptor.config_lora(
            alpha=params.get('alpha', 32),
            dropout=params.get('dropout', 0.05),
            r=params.get('r', 8),
            bias=params.get('bias', 'none'),
            task_type='CASUAL_LM'
        )
        adaptor.init_lora(adaptor.lora_config)

    def merge_adapter(self, adaptor, target_model_path, adapter_path):
        """
        Merges a trained adapter with a base model to create a complete model and saves the merged model.
        """
        # Load the base model
        print("Loading adapter...")
        model = adaptor.base_model_
        tokenizer = adaptor.tokenizer

        # Resize token embeddings to match the tokenizer's vocabulary size
        model.resize_token_embeddings(len(tokenizer))

        # Load the adapter and merge it with the base model
        model = PeftModel.from_pretrained(model, adapter_path)
        # Merge the adapter with the base model and unload the adapter
        model = model.merge_and_unload()

        # Save the merged model and tokenizer at the specified path
        print("Saving target model...")
        model.save_pretrained(target_model_path)
        tokenizer.save_pretrained(target_model_path)

    def train_model(self, adaptor, dataset):
        adaptor.train_data = self.prepare_llava_dataset(dataset)
        adaptor.train()

    def exe_lora_training(self, shared_list, params):
        try:
            gpu_list = get_GPU_Info(15, 'training', [3, 4, 5, 6])
            if gpu_list[0]:

                adaptor = self.init_adaptor_model(
                    params['run_lora_param'], gpu_list[1])
                self.set_training_arguments(
                    adaptor, params['set_training_arguments_param'])
                self.config_lora(adaptor, params['config_lora_param'])
                self.train_model(adaptor, params['dataset'])
                # self.merge_adapter(adaptor, params['finetune_model_output_dir'],
                #                    params['set_training_arguments_param']['adapter_output_dir'])
                release_memory()
                if validate_folder(params['set_training_arguments_param']['adapter_output_dir']):
                    shared_list.extend((True, ""))
                else:
                    shared_list.extend(
                        (False, "There seems to be a problem with the network. Please try again later."))
            else:
                shared_list.extend((False, gpu_list[2]))
        except Exception as error:
            msg = "Lora Training Error : {}".format(error)
            print(msg)
            shared_list.extend((False, msg))

    def run_lora(self, params):
        manager = Manager()
        shared_list = manager.list()
        process = Process(target=self.exe_lora_training,
                          args=(shared_list, params))
        process.start()
        process.join()
        return shared_list[0], shared_list[1]


if __name__ == "__main__":
    start_time = time.time()
    params = {
        'run_lora_param': {
            'tokenizer': 'meta-llava/llava-v1.5-7b',
            'base_model': 'meta-llava/llava-v1.5-7b',
            'cache_dir': "/home/devuser/testing/models/",
            'token': '',
        },

        'set_training_arguments_param': {
            'adapter_output_dir': '/home/devuser/testing/lora_adapter/user_model',
            'num_train_epochs': 1,
            'per_device_train_batch_size': 1,
            'learning_rate': 0.0002,
            'warmup_steps': 0,
            'optim': 'paged_adamw_8bit',
            'lr_scheduler_type': 'constant',
            'gradient_accumulation_steps': 1,
        },

        'config_lora_param': {
            'alpha': 32,
            'dropout': 0.05,
            'r': 8,
            'bias': 'none',
        },

        # 'finetune_model_output_dir': '/home/devuser/testing/fine_tune/user_model',

        'dataset': [
            {
                "id": "unique_id",
                "image": "image_file.jpg",
                "conversations": [
                    {
            
                        "from": "human",
                        "value": "What's your favorite hobby?"
            
                    },
                    {
                        "from": "gpt",
                        "value": "I'm passionate about entrepreneurship, technology, and space exploration. How about you?"
                    }
                ]
            }
        
        ],

    }
    print(FineTuneLLMLora().run_lora(params))
    print(f"Execution time: {time.time() - start_time} seconds")
