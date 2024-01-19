import os

# load_dotenv()
ROOT_DIRECTORY = os.path.dirname(os.path.realpath(__file__))

MODELS_PATH = "./models/"

# Can be changed to a specific number
INGEST_THREADS = os.cpu_count() or 8
HF_TOKEN = "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"

# Context Window and Max New Tokens
CONTEXT_WINDOW_SIZE = 4096
MAX_NEW_TOKENS = CONTEXT_WINDOW_SIZE  

# If you get a "not enough space in the buffer" error, you should reduce the values below, 
# start with half of the original values and keep halving the value until the error stops appearing

N_GPU_LAYERS = 100  # Llama-2-70B has 83 layers
N_BATCH = 512

MODEL_ID = "meta-llama/Llama-2-7b-chat-hf"
