from dotenv import load_dotenv
from langchain.chains import ConversationChain
try:
    from lora_finetune.gpu_allocation import get_GPU_Info
    from bot.prompt_template_utils import *
    from bot.load_models import load_llm_model_langchain
    from bot.constants import *
except Exception as error:
    from prompt_template_utils import *
    from load_models import load_llm_model_langchain
    from constants import *
    print("pipeline error: ", error)
import gc
gc.collect()

load_dotenv(".env")


def create_model_config():
    model_params = {
        'model_id': MODEL_ID,
        'cache_dir': MODELS_PATH,
        'max_new_tokens': MAX_NEW_TOKENS,
        'hf_token': HF_TOKEN,
        'gpu_list': '',
        # '':'',
    }
    return model_params


def start_model_llama2(custom_character_attribute, sender_user_message=None, shared_list=None):
    try:
        model_params = create_model_config()
        model_params['gpu_list'] = get_GPU_Info(18, 'chat', [3, 4, 5])
    except:
        model_params['gpu_list'] = [True, {3: "18GB", }, ""]

    if model_params['gpu_list'][0]:
        system_prompt = create_persona_template(
            custom_character_attribute['charName'], custom_character_attribute)
        LLM = load_llm_model_langchain(model_params)
        prompt, memory = get_prompt_template(
            system_prompt=system_prompt, LLM=LLM)
        conversation = ConversationChain(
            llm=LLM, verbose=False, prompt=prompt, memory=memory)

        if sender_user_message is not None:
            response = conversation.invoke(sender_user_message)
            shared_list.extent(response, True)
        else:
            return conversation
    else:
        return shared_list.extent(model_params['gpu_list'][2], False)


if __name__ == "__main__":
    from persona_character_attributes import *
    custom_character_attribute = {}
    custom_character_attribute['charName'] = "Elon Musk"
    custom_character_attribute['initial_message'] = "Hello, I am Elon Musk"
    custom_character_attribute.update(elon_musk_attributes)
    print('Type exit for exiting conversation')
    conversation = start_model_llama2(custom_character_attribute)
    if not custom_character_attribute['initial_message'].strip() in [None, ""]:
        print(
            f"Hello I am {custom_character_attribute['charName']}, {custom_character_attribute['initial_message']}")
    else:
        print(
            f"Hello I am {custom_character_attribute['charName']}, How can I help you today.")
    while True:
        user_input = input("User:- ")
        if user_input.lower() == "exit":
            print("Exiting the conversation.")
            break
        character_response = conversation.invoke(user_input)
        response = character_response["response"].replace("\n\n", " ")
        print(f"{custom_character_attribute['charName']}:-", response)
