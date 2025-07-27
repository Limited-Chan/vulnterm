import pandas as pd
import numpy as np
from sentence_transformers import SentenceTransformer
import os

df = pd.read_csv("cve-summary.csv", header=None, names=["CVE_ID", "CVSS", "Summary"])

model = SentenceTransformer("all-MiniLM-L6-v2")

summaries = df["Summary"].astype(str).tolist()
vectors = model.encode(summaries)

os.makedirs("data", exist_ok=True)

np.save("data/cve_vectors_sbert.npy", vectors)
np.save("data/cve_vocab_ids.npy", df["CVE_ID"].values)