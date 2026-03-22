import requests
import faiss
import numpy as np

from sentence_transformers import SentenceTransformer as st

model = st('all-MiniLM-L6-v2')


with open('cyber_data.txt', 'r') as f:
    sentences=f.read().splitlines()

sentences = [s.strip() for s in sentences]

embeddings = model.encode(sentences)
embeddings=np.array(embeddings)

demension = embeddings.shape[1]
index = faiss.IndexFlatL2(demension)
index.add(embeddings)


query = """
Failed password for root from 192.168.1.10
Failed password for root from 192.168.1.10
Failed password for root from 192.168.1.10
"""

query_embedding = model.encode([query])
query_embedding = np.array(query_embedding)


k=3
distances, indices = index.search(query_embedding, k)


contexts=[sentences[i] for i in indices[0]]
context="\n".join(contexts)



prompt = f"""
You are a cybersecurity analyst.
STRICT RULE:
Only use the provided context. Dont guess

Analyze the following log:
"{query}"

Context:
"{context}"

Tasks:
1. Identify the type of attack.
2.Explain why
3. Give Severity
4. Suggest Mitigation

"""




def ask_llm(prompt):
    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": "mistral",
            "prompt": prompt,
            "stream": False
        }
    )
    return response.json()["response"]

result = ask_llm(prompt)
print(result)
