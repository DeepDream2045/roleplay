from dotenv import load_dotenv
import torch
import subprocess
from langchain.chains import ConversationChain
try:
    from bot.persona_character_attributes import *
    from bot.prompt_template_utils import *
    from bot.load_models import load_llm_model_langchain
    from bot.constants import MODEL_ID, MODELS_PATH
except Exception as error:
    from persona_character_attributes import *
    from prompt_template_utils import *
    from load_models import load_llm_model_langchain
    from constants import MODEL_ID, MODELS_PATH
    print("pipeline error: ", error)
import gc
gc.collect()

load_dotenv(".env")


def load_llama2_model():
    if torch.backends.mps.is_available():
        DEVICE_TYPE = "mps"
    elif torch.cuda.is_available():
        DEVICE_TYPE = "cuda"
    else:
        DEVICE_TYPE = "cpu"

    # Load model and pipeline
    LLM = load_llm_model_langchain(
        model_id=MODEL_ID, device_type=DEVICE_TYPE, cache_dir=MODELS_PATH, set_manual_gpu=True)
    return LLM


def start_model_llama2(custom_character_attribute):

    # Main code
    LLM = load_llama2_model()
    if not custom_character_attribute['initial_message'].strip() in [None, ""]:
        print(
            f"Hello I am {custom_character_attribute['charName']}, {custom_character_attribute['initial_message']}")
    else:
        print(
            f"Hello I am {custom_character_attribute['charName']}, How can I help you today.")
    system_prompt = create_persona_template(
        custom_character_attribute['charName'], custom_character_attribute)
    prompt, memory = get_prompt_template(system_prompt=system_prompt, LLM=LLM)

    conversation = ConversationChain(
        llm=LLM, verbose=False, prompt=prompt, memory=memory)
    return conversation


if __name__ == "__main__":
    custom_character_attribute = {}
    custom_character_attribute['charName'] = "Elon Musk"
    custom_character_attribute['initial_message'] = "Hello, I am Elon Musk"
    custom_character_attribute.update(elon_musk_attributes)
    print('Type exit for exiting conversation')
    conversation = start_model_llama2(custom_character_attribute)
    while True:
        user_input = input("User:- ")
        if user_input.lower() == "exit":
            print("Exiting the conversation.")
            break
        print("user_input:-", user_input)
        character_response = conversation.invoke(user_input)
        response = character_response["response"].replace("\n\n", "\n")
        print(response)
        print(f"{custom_character_attribute['charName']}:-", response)
        print()
