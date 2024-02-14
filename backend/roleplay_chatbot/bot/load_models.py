import torch
from langchain_community.llms.huggingface_pipeline import HuggingFacePipeline
from transformers import AutoModelForCausalLM, AutoTokenizer
from transformers import (
    GenerationConfig, pipeline,
)
import math
from dotenv import load_dotenv
load_dotenv(".env")

try:
    from bot.constants import  MAX_NEW_TOKENS, HF_TOKEN
except Exception as error:
    print("Load_ model :", error)
    from constants import  MAX_NEW_TOKENS, HF_TOKEN

def find_available_gpus():
    """
    Find all available GPUs in the system.

    Returns:
    - gpu_list (list): A list of GPU indices available in the system.
    """
    gpu_list = []
    if torch.cuda.is_available():
        num_gpus = torch.cuda.device_count()
        for i in range(num_gpus):
            gpu_list.append(i)
    if gpu_list:
        return gpu_list
    else:
        print("No GPUs found in the system.")
        return False

def get_gpu_memory_usage(gpu_id):
    """
    Get the free memory space available on the specified GPU.

    Parameters:
    - gpu_id (int): The index of the GPU.

    Returns:
    - free_memory (float): The free memory space in GB on the specified GPU.
    """
    if torch.cuda.is_available():
        # Select the specified GPU
        torch.cuda.set_device(gpu_id)

        # Get the total and free memory on the selected GPU
        total_memory = torch.cuda.get_device_properties(gpu_id).total_memory
        allocated_memory = torch.cuda.memory_allocated(gpu_id)
        cached_memory = torch.cuda.memory_reserved(gpu_id)
        free_memory = total_memory - allocated_memory - cached_memory

        # Convert bytes to GB
        free_memory_gb = free_memory / (1024 ** 3)
        return free_memory_gb
    else:
        print("CUDA is not available.")
        return None

def get_device_memory():
    import subprocess as sp
    command = "nvidia-smi --query-gpu=memory.free --format=csv"
    memory_free_info = sp.check_output(command.split()).decode('ascii').split('\n')[:-1][1:]
    memory_free_values = [int(x.split()[0]) for i, x in enumerate(memory_free_info)]
    return memory_free_values

def get_GPU_info(llm_size = 16):
    try:
        gpu_dict = {}
        used_dict = {}
        gpu_list = find_available_gpus()
        used_dict = dict(zip(gpu_list, get_device_memory()))
        split_size = math.ceil(llm_size/len(gpu_list)) + 1
        if gpu_list:
            for i in gpu_list:
                if used_dict[i] > split_size:
                    gpu_dict[i] = str(split_size)+"GB"
            return gpu_dict
    except Exception as error:
        print(error)
        return {3:"4GB", 4:"4GB", 5:"4GB", 6:"4GB"}


def load_full_model(model_id, device_type, cache_dir, gpu_list) :
    """
    Load a full model using either LlamaTokenizer or AutoModelForCausalLM.

    This function loads a full model based on the specified device type.
    If the device type is 'mps' or 'cpu', it uses LlamaTokenizer and LlamaForCausalLM.
    Otherwise, it uses AutoModelForCausalLM.

    Parameters:
    - model_id (str): The identifier for the model on HuggingFace Hub.
    - device_type (str): The type of device where the model will run.

    Returns:
    - model AutoModelForCausalLM: The loaded model.
    - tokenizer AutoTokenizer: The tokenizer associated with the model.

    Notes:
    - The function uses the `from_pretrained` method to load both the model and the tokenizer.
    - Additional settings are provided for NVIDIA GPUs, such as loading in 4-bit and setting the compute dtype.
    """

    tokenizer = AutoTokenizer.from_pretrained(model_id, cache_dir=cache_dir, token=HF_TOKEN)
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        device_map="auto",
        torch_dtype=torch.float16,
        low_cpu_mem_usage=True,
        trust_remote_code=True,  # set these if you are using NVIDIA GPU
        max_memory=gpu_list,
        token=HF_TOKEN
        #, cache_dir=MODELS_PATH,
        #load_in_4bit=True,
        #bnb_4bit_quant_type="nf4",
        #bnb_4bit_compute_dtype=torch.float16,
    )
    model.tie_weights()
    return model, tokenizer

def load_llm_model_langchain(model_id, device_type, cache_dir, set_manual_gpu=False):
    if not set_manual_gpu:
        gpu_list = get_GPU_info()
    else:
        gpu_list = {3:"4GB", 4:"4GB", 5:"4GB", 6:"4GB"}

    model, tokenizer = load_full_model(model_id, device_type, cache_dir, gpu_list)
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

