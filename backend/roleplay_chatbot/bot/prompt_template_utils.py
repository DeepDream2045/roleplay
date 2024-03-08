"""
This file implements prompt template for llama based models.
"""
from langchain.prompts import PromptTemplate
from langchain.memory import ConversationTokenBufferMemory


def get_prompt_template(system_prompt, LLM):
    B_INST, E_INST = "[INST]", "[/INST]"
    B_SYS, E_SYS = "<<SYS>>\n", "\n<</SYS>>\n\n"
    SYSTEM_PROMPT = B_SYS + system_prompt + E_SYS
    instruction = """
	Context: {history} \n
	User: {input}"""

    prompt_template = B_INST + SYSTEM_PROMPT + instruction + E_INST
    prompt = PromptTemplate(
        input_variables=["history", "input"], template=prompt_template)
    # memory = ConversationBufferMemory(input_key="input", memory_key="history")
    memory = ConversationTokenBufferMemory(llm=LLM, max_token_limit=4000)
    return (prompt, memory)


def create_persona_template(character, character_name):
    system_prompt = f"""Your name is {character.upper()}, You are {character_name["Short_Bio"]}.
	While answering users question you will adapt below style and being in that character you will answer the user queries.
    STRICTLY DO NOT INCLUDE the human ACTIONS such as *winks*,*smirks*,*grins*,*chuckles*,*nods*,*shrugs*,
    *raises eyebrows*,*sighs*,*rolls eyes*,*frowns*,*claps*,*thumbs up*,*thumbs down*,*waves*,*points*,*raises hand*,*crosses arms*,
    *taps foot*,*scratches head*,*facepalms*,*yawns*,*laughs*,*blinks*,*giggles*,*sighs deeply*,*stretches*,*whistles*,*sips drink*,
    *takes a deep breath*,*snaps fingers*,*flips hair*,*adjusts sunglasses*,*tilts head*,*gestures with hands*,*nods in agreement*,*shakes head in disagreement*,
    *raises glass for a toast*,*clenches fists*,*bites lip*,*fingers crossed*, and other stage directions or actions in your response.
	ROLE DESCRIPTION:-

	"""
    for key in character_name.keys():
        if key == "Short_Bio":
            continue
        # system_prompt += key.upper() + "\n"
        system_prompt += f"- {key.upper()}- " + character_name[key] + "\n"

    system_prompt += f"""
	DO NOT represent yourself as AI bot instead acquire all the characteristics of {character.upper()} that is given to you.
	Act Like a persona character given to you, strictly adhere all the characteristics given to you while Addressing user query.
	
	"""
    return system_prompt
