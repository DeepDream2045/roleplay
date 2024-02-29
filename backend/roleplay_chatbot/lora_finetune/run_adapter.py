from base_lora import LoraModel
import re
import torch
from transformers import BitsAndBytesConfig


class RunLoraAdapter:
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

    def run_adapter(self, params):
        try:
            adaptor = self.init_adaptor_model(params['model_param'])
            adaptor.load_adaptor(params['adapter_path'])
            output = adaptor.generate(params['text'])
            output = re.sub("<.*?>", "", output)
            response = output.split('?')[1].strip()
            return response
        except Exception as error:
            msg = "Lora Adapter Error : {}".format(error)
            print(msg)
            return msg


if __name__ == "__main__":
    params = {
        'model_param': {
            'tokenizer': 'meta-llama/Llama-2-7b-chat-hf',
            'base_model': 'meta-llama/Llama-2-7b-chat-hf',
            'cache_dir': "/home/devuser/testing/models/",
            'token': '',
        },
        'adapter_path': "/home/devuser/testing/lora_adapter/user_model",
        'text': "What's your favorite hobby?"
    }
    print(RunLoraAdapter().run_adapter(params))
