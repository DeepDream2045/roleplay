import math
import torch

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


def get_device_memory():
    import subprocess as sp
    command = "nvidia-smi --query-gpu=memory.free --format=csv"
    memory_free_info = sp.check_output(
        command.split()).decode('ascii').split('\n')[:-1][1:]
    memory_free_values = [int(x.split()[0])
                          for i, x in enumerate(memory_free_info)]
    return memory_free_values

def allocate_single_gpu(gpu_list, gpu_free_dict, model_size):
    gpu_assigned = {}
    if gpu_list:
        for loc in gpu_list:
            if gpu_free_dict[loc] > model_size*1000:
                gpu_assigned[loc] = str(model_size)+"GB"
                break
    if len(gpu_assigned.keys())>0:
        return True, gpu_assigned, ""
    return False, {}, "There seems to be a problem with the network. Please try again later."

def allocate_split_gpu(gpu_list, gpu_free_dict, model_size):
    gpu_assigned = {}
    split_size = model_size
    for i in gpu_list:
        memory = math.floor(gpu_free_dict[i]/1000)
        if memory > 1 and split_size > 0:
            if memory > split_size:
                gpu_assigned[i] = str(split_size)+"GB"
                break
            else:
                split_size = split_size - (memory-1)
                gpu_assigned[i] = str(memory-1)+"GB"
    
    if len(gpu_assigned.keys())>0:
        return True, gpu_assigned, ""
    return False, {}, "There seems to be a problem with the network. Please try again later."

def allocate_gpu_for_chat(gpu_list, gpu_free_dict, model_size):
    if gpu_list:
        is_split = allocate_single_gpu(gpu_list, gpu_free_dict, model_size)
        if not is_split[0]:
            return allocate_split_gpu(gpu_list, gpu_free_dict, model_size)
        return is_split

def check_gpu_memory(model_size, used_dict):
    total_memory = 0
    for key, val in used_dict.items():
        total_memory = total_memory + (math.floor(val/1000) - 1)
    if total_memory > model_size:
        return True
    return False

def get_GPU_Info(llm_size=150, flag='chat', custom_gpu_list = None):
    try:
        used_dict = {}
        gpu_list = find_available_gpus()
        used_dict = dict(zip(gpu_list, get_device_memory()))
        if custom_gpu_list is not None:
            new_gpu_dict = {}
            for i in custom_gpu_list:
                new_gpu_dict[i] = used_dict[i]
        else:
            new_gpu_dict = used_dict
        if check_gpu_memory(llm_size, new_gpu_dict):
            if flag == 'training':
                return allocate_single_gpu(list(new_gpu_dict.keys()), new_gpu_dict, llm_size)
            elif flag in ['chat', 'run_adapter']:
                return allocate_gpu_for_chat(list(new_gpu_dict.keys()), new_gpu_dict, llm_size)
            else:
                return False, {}, "There seems to be a problem with the network. Please try again later."
        else:
            return False, {}, "There seems to be a problem with the network. Please try again later."

    except Exception as error:
        print(error)
        return False, {}, "There seems to be a problem with the network. Please try again later."

if __name__ == "__main__":
    print(get_GPU_Info(150, 'run_adapter', [3, 4, 5, 6]))