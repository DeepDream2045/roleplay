from transformers import AutoModelForCausalLM, AutoTokenizer, GenerationConfig
from peft import LoraConfig, PeftModel, get_peft_model, prepare_model_for_int8_training
from trl import SFTTrainer
import torch
import gc

# import commune
# Model = commune.module('model')
# class LoraModel(Model):


def release_memory():
    try:
        gc.collect()
        torch.cuda.empty_cache()
    except:
        pass


class LoraModel():
    def __init__(self):
        # self.init_model()
        self.tokenizer = None
        self.base_model_ = None
        self.lora_model_ = None
        self.trainer = None
        self.train_data = None
        self.lora_config = None
        self.gen_config = None
        self.use_quant = True

    def init_tokenizer(self, base_model_name='meta-llama/Llama-2-7b-chat-hf', cache_dir=None, token=None):
        try:
            if self.tokenizer:
                self.tokenizer = None
                # self.release_memory()
                try:
                    gc.collect()
                    torch.cuda.empty_cache()
                except:
                    pass
            self.tokenizer = AutoTokenizer.from_pretrained(
                base_model_name, cache_dir=cache_dir, token=token, use_fast=False)
            if not self.tokenizer.pad_token:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            self.tokenizer.padding_side = 'right'
        except:
            self.tokenizer = None
            # self.release_memory()
            try:
                gc.collect()
                torch.cuda.empty_cache()
            except:
                pass

            raise ValueError("Base Tokenizer init failure")

    def init_base_model(self, base_model_name='meta-llama/Llama-2-7b-chat-hf', quant_config=None, cache_dir=None, token=None, gpu_list=None):
        try:
            self.base_model_name = base_model_name
            if self.base_model_:
                self.base_model_ = None
                release_memory()

            self.base_model_ = AutoModelForCausalLM.from_pretrained(
                base_model_name,
                quantization_config=quant_config,
                device_map="auto",
                max_memory=gpu_list,
                torch_dtype=torch.float16,
                low_cpu_mem_usage=True,
                trust_remote_code=True,
                cache_dir=cache_dir,
                token=token,
            )

            self.base_model_.config.use_cache = False
            self.base_model_.config.pretraining_tp = 1
        except:
            self.base_model_ = None
            self.base_model_name = None
            # self.release_memory()
            try:
                gc.collect()
                torch.cuda.empty_cache()
            except:
                pass

            raise ValueError("Base LLM init failure")

    def config_lora(self, alpha=64, dropout=0.05, r=32, bias='none', task_type='CAUSAL_LM'):
        self.lora_config = LoraConfig(
            lora_alpha=alpha,
            lora_dropout=dropout,
            r=r,
            bias=bias,
            task_type=task_type,
            target_modules=[
                "q_proj",
                "k_proj",
                "v_proj",
                "o_proj",
                "gate_proj",
                "up_proj",
                "down_proj",
                "lm_head",
            ]
        )

    def init_lora(self, lora_config):
        try:
            self.lora_model_ = get_peft_model(self.base_model_, lora_config)
            self.lora_model_ = prepare_model_for_int8_training(
                self.lora_model_)
        except:
            self.lora_model_ = None
            # self.release_memory()
            try:
                gc.collect()
                torch.cuda.empty_cache()
            except:
                pass

            raise ValueError("LoRA init failure")

    def train(self):
        if not self.train_data:
            raise ValueError("Empty training data")

        if not self.training_params:
            raise ValueError("Invalid training parameters")

        if not self.lora_model_:
            raise ValueError("LoRA init failure")

        if not self.base_model_ or not self.tokenizer:
            raise ValueError("Base model init failure")

        self.trainer = SFTTrainer(
            model=self.base_model_,
            train_dataset=self.train_data,
            peft_config=self.lora_config,
            dataset_text_field='prediction',
            tokenizer=self.tokenizer,
            args=self.training_params,
            packing=True
        )
        self.trainer.train()
        self.trainer.model.save_pretrained(self.training_params.output_dir)

    def load_adaptor(self, adaptor_path, gpu_list):
        if adaptor_path != '':
            self.lora_model_ = PeftModel.from_pretrained(
                self.base_model_,
                adaptor_path,
                device_map="auto",
                max_memory=gpu_list,
            )
        elif adaptor_path == '':
            self.lora_model_ = self.base_model_

    def generate(self, prompt):
        self.gen_config = GenerationConfig(
            temperature=0.5,
            top_p=0.75,
            top_k=40,
            num_beams=4,
            no_repeat_ngram_size=3
        )
        inputs = self.tokenize(prompt).input_ids

        with torch.no_grad():
            gen_output = self.lora_model_.generate(
                input_ids=inputs.cuda(),
                generation_config=self.gen_config,
                return_dict_in_generate=True,
                output_scores=True,
                max_new_tokens=4096,
            )
            s = gen_output.sequences[0]
            self.gen_output = self.tokenizer.decode(s)
            return self.gen_output

    def tokenize(self, text: str = 'What\'s up?'):
        return self.tokenizer(text, return_tensors='pt')

    def encode(self, text: str, token_id: int = None, **kwargs) -> torch.Tensor:
        encoded_text = self.tokenize(text)

        return encoded_text
