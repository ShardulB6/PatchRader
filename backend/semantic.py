"""On-demand IBM Granite embedding similarity. CPU friendly for a small CVE subset."""
from functools import lru_cache
import numpy as np

MODEL_ID='ibm-granite/granite-embedding-30m-english'

@lru_cache(maxsize=1)
def encoder():
    from sentence_transformers import SentenceTransformer
    return SentenceTransformer(MODEL_ID,device='cpu')

def similar_cves(store,cve_id,limit=8,candidate_count=350):
    # On-demand embed the query and a small candidate pool: top-ranked scoreboard
    # + historical KEV. Not a full 400k nearest-neighbor search.
    target=store.cve(cve_id)
    if target.empty: return None,None
    a=store.query('''SELECT cve_id,description FROM vulnerabilities
       WHERE cve_id IN (SELECT cve_id FROM known_exploited) AND description IS NOT NULL''')
    b=store.query('''SELECT v.cve_id,v.description FROM vulnerabilities v JOIN
      (SELECT cve_id,ROW_NUMBER() OVER (ORDER BY
       (COALESCE(TRY_CAST(exploitdb AS INTEGER),0)+COALESCE(TRY_CAST(metasploit AS INTEGER),0)+
        COALESCE(TRY_CAST(nuclei AS INTEGER),0)+COALESCE(TRY_CAST(poc_github AS INTEGER),0)>0) DESC,
        COALESCE(TRY_CAST(epss AS DOUBLE),0) DESC) AS r FROM scoreboard) s USING(cve_id)
       WHERE s.r<=? AND v.description IS NOT NULL''',[int(candidate_count)])
    import pandas as pd
    pool=pd.concat([a,b],ignore_index=True).drop_duplicates('cve_id')
    pool=pool[pool.cve_id != cve_id].copy()
    text=str(target.iloc[0].get('description') or '')
    if not text.strip(): return None,None
    texts=[text]+pool.description.fillna('').astype(str).tolist()
    embeddings=encoder().encode(texts,batch_size=32,normalize_embeddings=True,convert_to_numpy=True,
                                 show_progress_bar=False)
    sim=embeddings[1:]@embeddings[0]
    pool['cosine_similarity']=sim
    pool=pool.nlargest(limit,'cosine_similarity').copy()
    kev=store.query('SELECT cve_id,date_added FROM known_exploited')
    pool=pool.merge(kev,on='cve_id',how='left')
    return pool,MODEL_ID
