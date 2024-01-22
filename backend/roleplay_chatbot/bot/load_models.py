import torch
from langchain_community.llms.huggingface_pipeline import HuggingFacePipeline
# from langchain.llms import HuggingFacePipeline
# from huggingface_hub import hf_hub_download
from transformers import AutoModelForCausalLM, AutoTokenizer, LlamaForCausalLM, LlamaTokenizer
from transformers import (
    GenerationConfig,
    pipeline,
)
from dotenv import load_dotenv
load_dotenv(".env")
try:
    from bot.constants import  MAX_NEW_TOKENS, HF_TOKEN
except Exception as error:
    print("Load_ model :", error)
    from constants import  MAX_NEW_TOKENS, HF_TOKEN


def load_full_model(model_id, device_type, cache_dir) :
    """
    Load a full model using either LlamaTokenizer or AutoModelForCausalLM.

    This function loads a full model based on the specified device type.
    If the device type is 'mps' or 'cpu', it uses LlamaTokenizer and LlamaForCausalLM.
    Otherwise, it uses AutoModelForCausalLM.

    Parameters:
    - model_id (str): The identifier for the model on HuggingFace Hub.
    - device_type (str): The type of device where the model will run.

    Returns:
    - model (Union[LlamaForCausalLM, AutoModelForCausalLM]): The loaded model.
    - tokenizer (Union[LlamaTokenizer, AutoTokenizer]): The tokenizer associated with the model.

    Notes:
    - The function uses the `from_pretrained` method to load both the model and the tokenizer.
    - Additional settings are provided for NVIDIA GPUs, such as loading in 4-bit and setting the compute dtype.
    """

    if device_type.lower() in ["mps", "cpu"]:
        tokenizer = LlamaTokenizer.from_pretrained(model_id, cache_dir=cache_dir, token=HF_TOKEN)
        model = LlamaForCausalLM.from_pretrained(model_id, cache_dir=cache_dir, token=HF_TOKEN)
    else:
        tokenizer = AutoTokenizer.from_pretrained(model_id, cache_dir=cache_dir, token=HF_TOKEN)
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            device_map="auto",
            torch_dtype=torch.float16,
            low_cpu_mem_usage=True,
            #cache_dir=MODELS_PATH,
            trust_remote_code=True,  # set these if you are using NVIDIA GPU
            #load_in_4bit=True,
            #bnb_4bit_quant_type="nf4",
            #bnb_4bit_compute_dtype=torch.float16,
            max_memory={3:"30GB"},  # Uncomment this line with you encounter CUDA out of memory errors
            token=HF_TOKEN
        )
        model.tie_weights()
    return model, tokenizer



def load_llm_model_langchain(model_id, device_type, cache_dir):
    model, tokenizer = load_full_model(model_id, device_type, cache_dir)
    # Load configuration from the model to avoid warnings
    generation_config = GenerationConfig.from_pretrained(model_id)
    # Create a pipeline for text generation
    pipe = pipeline(
        "text-generation",
        model=model,
        tokenizer=tokenizer,
        max_length=MAX_NEW_TOKENS,
        temperature=0.2,
        top_p=0.95,
        do_sample=True,
        repetition_penalty=1.15,
        generation_config=generation_config,
    )
    local_llm = HuggingFacePipeline(pipeline=pipe)

    return local_llm



