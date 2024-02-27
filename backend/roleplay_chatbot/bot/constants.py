import os
ROOT_DIRECTORY = os.path.dirname(os.path.realpath(__file__))

MODELS_PATH = "./models/"
MODEL_ID = "meta-llama/Llama-2-7b-chat-hf"
HF_TOKEN = ""

# Context Window and Max New Tokens
CONTEXT_WINDOW_SIZE = 4096
MAX_NEW_TOKENS = CONTEXT_WINDOW_SIZE
