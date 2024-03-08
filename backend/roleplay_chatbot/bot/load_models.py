import torch
from langchain_community.llms.huggingface_pipeline import HuggingFacePipeline
from transformers import AutoModelForCausalLM, AutoTokenizer
from transformers import GenerationConfig, pipeline


def load_full_model(model_params):
    """
    Load a full model using either LlamaTokenizer or AutoModelForCausalLM.

    Notes:
    - The function uses the `from_pretrained` method to load both the model and the tokenizer.
    - Additional settings are provided for NVIDIA GPUs, 
      such as loading in 4-bit and setting the compute dtype.
    """
    tokenizer = AutoTokenizer.from_pretrained(
        model_params['model_id'], cache_dir=model_params['cache_dir'], token=model_params['hf_token'])
    model = AutoModelForCausalLM.from_pretrained(
        model_params['model_id'],
        device_map="auto",
        max_memory=model_params['gpu_list'][1],
        cache_dir=model_params['cache_dir'],
        token=model_params['hf_token'],
        torch_dtype=torch.float16,
        low_cpu_mem_usage=True,
        trust_remote_code=True,
        # load_in_4bit=True,
        # bnb_4bit_quant_type="nf4",
        # bnb_4bit_compute_dtype=torch.float16,
    )
    model.tie_weights()
    return model, tokenizer


def load_llm_model_langchain(model_params):
    model, tokenizer = load_full_model(model_params)
    # Load configuration from the model to avoid warnings
    generation_config = GenerationConfig.from_pretrained(
        model_params['model_id'])
    # Create a pipeline for text generation
    pipe = pipeline(
        "text-generation",
        model=model,
        tokenizer=tokenizer,
        max_length=model_params['max_new_tokens'],
        temperature=0.2,
        top_p=0.95,
        do_sample=True,
        repetition_penalty=1.15,
        generation_config=generation_config,
    )
    local_llm = HuggingFacePipeline(pipeline=pipe)
    return local_llm
