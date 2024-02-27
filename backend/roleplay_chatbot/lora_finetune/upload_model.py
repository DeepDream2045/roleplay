from transformers import AutoModel, AutoTokenizer, AutoConfig
from huggingface_hub import HfApi, HfFolder


def upload_lm_to_huggingface(model, tokenizer, model_info):

    config = AutoConfig.from_pretrained(model_info['model_path'])
    # Initialize the Hugging Face API and folder
    api = HfApi()
    folder = HfFolder()

    # Push the model to the Hugging Face hub
    api.create_repo(token=model_info['token'],
                    name=model_info['model_name'], exist_ok=True)

    # Push the model files to the hub
    folder.push_to_hub(model=model, tokenizer=tokenizer,
                       config=config, repo_id=model_info['model_name'])

    # Optionally, push additional files such as training scripts, README, etc.
    if model_info['additional_files_path']:
        folder.push_to_hub(
            path=model_info['additional_files_path'], repo_id=model_info['model_name'])


if __name__ == "__main__":
    model_info = {
        # Example usage
        "model_name": "your_model_name",
        "model_path": "path_to_your_model_directory",
        "token": "your_hugging_face_api_token",
        "additional_files_path": "path_to_additional_files_directory",
    }
    # Load the model and tokenizer
    model = AutoModel.from_pretrained(model_info['model_path'])
    tokenizer = AutoTokenizer.from_pretrained(model_info['model_path'])

    upload_lm_to_huggingface(model, tokenizer, model_info)
