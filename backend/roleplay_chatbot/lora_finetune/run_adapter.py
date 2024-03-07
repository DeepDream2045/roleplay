from .adapter_base import LoraModel, release_memory
from .gpu_allocation import get_GPU_Info
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

    def init_adaptor_model(self, params, gpu_list):
        adaptor = LoraModel()
        adaptor.init_tokenizer(
            params['tokenizer'], cache_dir=params['cache_dir'], token=params['token'])
        adaptor.init_base_model(params['base_model'], self.create_quant_config(
        ), cache_dir=params['cache_dir'], token=params['token'], gpu_list=gpu_list)
        return adaptor

    def run_adapter(self, params):
        try:
            gpu_list = get_GPU_Info(10, 'run_adapter', [3, 4, 5, 6])
            if gpu_list[0]:
                adaptor = self.init_adaptor_model(
                    params['model_param'], gpu_list[1])
                adaptor.load_adaptor(params['adapter_path'], gpu_list[1])
                output = adaptor.generate(params['text'])
                output = re.sub("<.*?>", "", output).replace("\n\n", "")
                response = output.split(params['text'])[1].strip()
                adaptor.lora_model_ = None
                release_memory()
                return response, False
            else:
                return gpu_list[2], True
        except Exception as error:
            msg = "Run Lora Adapter Error : {}".format(error)
            return msg, True


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
