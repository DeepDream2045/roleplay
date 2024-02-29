from .base_lora import LoraModel
import time
import torch
from transformers import BitsAndBytesConfig, TrainingArguments
from datasets import Dataset
from peft import PeftModel
import pandas as pd


class FineTuneLLMLora:
    def prep_data(self, data):
        # Convert to pandas dataframe for convenient processing
        rd_df = pd.DataFrame.from_records(data)

        # Define template and format data into the template for supervised fine-tuning
        template = """Below is an instruction that describes a task. Write a response that appropriately completes the request.\n"""
        template = template + """\n### Context:\n{} """
        rd_df['prediction'] = rd_df["context"].apply(
            lambda x: template.format(x))
        rd_df.drop(columns=['context'], inplace=True)
        return Dataset.from_dict(rd_df)

    def create_quant_config(self):
        return BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type='nf4',
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=False
        )

    def init_adaptor_model(self, params):
        adaptor = LoraModel()
        adaptor.init_tokenizer(
            params['tokenizer'], cache_dir=params['cache_dir'], token=params['token'])
        adaptor.init_base_model(params['base_model'], self.create_quant_config(
        ), cache_dir=params['cache_dir'], token=params['token'])
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
        adaptor.train_data = self.prep_data(dataset)
        adaptor.train()

    def run_lora(self, params):
        try:
            adaptor = self.init_adaptor_model(params['run_lora_param'])
            self.set_training_arguments(
                adaptor, params['set_training_arguments_param'])
            self.config_lora(adaptor, params['config_lora_param'])
            self.train_model(adaptor, params['dataset'])
            # self.merge_adapter(adaptor, params['finetune_model_output_dir'],
            #                    params['set_training_arguments_param']['adapter_output_dir'])
            return True
        except Exception as error:
            msg = "Lora Training Error : {}".format(error)
            print(msg)
            return msg


if __name__ == "__main__":
    start_time = time.time()
    print(f"Execution time: {time.time() - start_time} seconds")
    params = {
        'run_lora_param': {
            'tokenizer': 'meta-llama/Llama-2-7b-chat-hf',
            'base_model': 'meta-llama/Llama-2-7b-chat-hf',
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
                "context": "What's your favorite hobby?",
                "response": "I'm passionate about entrepreneurship, technology, and space exploration. How about you?"
            },
            {
                "context": "Can you tell me more about yourself?",
                "response": "Sure! I'm Elon Musk, CEO of SpaceX and Tesla, among other ventures. I'm focused on pioneering electric vehicles, space exploration, and renewable energy."
            },
            {
                "context": "What do you think about the future of space exploration?",
                "response": "I believe the future of space exploration is incredibly exciting! We're working on revolutionary projects to make space travel more accessible and sustainable."
            },
        ],
    }
    FineTuneLLMLora().run_lora(params)
