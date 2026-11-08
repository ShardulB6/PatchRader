import os
from pathlib import Path
import streamlit as st
import pandas as pd
import plotly.express as px
from dotenv import load_dotenv
from db import DataStore
from analyst import classify, execute_plan, grounded_answer, watsonx_enabled

load_dotenv()
BASE=Path(__file__).resolve().parent
st.set_page_config(page_title='PatchRadar | Vulnerability Intelligence',page_icon='🛡️',layout='wide',initial_sidebar_state='expanded')
st.markdown('''<style>
.block-container{padding-top:1.7rem; max-width:1450px;}
[data-testid="stSidebar"]{background:linear-gradient(175deg,#111d30,#132b37);}
[data-testid="stSidebar"] *{color:#f3f7fb !important;}
.hero{border-radius:18px;padding:27px 30px;background:linear-gradient(110deg,#14263d,#123e48);color:#f7fafc;margin-bottom:17px}
.hero h1{color:white;font-size:2.2rem; margin:0 0 6px 0}
.hero p{color:#d1e3ee;margin:0}
.evidence{padding:13px;border:1px solid #627f8a55;border-radius:12px;background:#607b8110}
.small-caption{font-size:.81rem;color:#78909c}
</style>''',unsafe_allow_html=True)

@st.cache_resource(show_spinner='Connecting to vulnerability data...')
def get_store(path):
    return DataStore(path)

st.sidebar.markdown('## 🛡️ PatchRadar')
st.sidebar.caption('Before the Breach · IBM Datathon')
base_dir=os.getenv('PATCHRADAR_DATA_DIR','data')
initial=str((BASE/base_dir).resolve()) if not Path(base_dir).is_absolute() else base_dir
data_dir=st.sidebar.text_input('Dataset folder', value=initial)
try:
    db=get_store(data_dir)
except Exception as exc:
    st.error(str(exc))
    st.info('Put the competition CSVs in `data/` next to `app.py`. See README.md for setup.')
    st.stop()

page=st.sidebar.radio('Navigate', ['Overview','Ask the Data','Priority Queue','CVE Investigator','Dataset Explorer'],label_visibility='collapsed')
st.sidebar.divider()
use_ai=st.sidebar.toggle('IBM watsonx Granite chatbot', value=watsonx_enabled(), disabled=not watsonx_enabled(), help='Requires credentials in .env and optional IBM SDK.')
if watsonx_enabled(): st.sidebar.success('watsonx credentials detected')
else: st.sidebar.info('Local analytics mode · Add watsonx credentials to enable generative answers')
st.sidebar.caption('Ranking uses exploit evidence first, EPSS second. KEV coverage ends Dec 2025 in supplied files.')

if page=='Overview':
    st.markdown('<div class="hero"><h1>Vulnerability Intelligence</h1><p>From hundreds of thousands of disclosures to a focused investigation queue.</p></div>', unsafe_allow_html=True)
    stats=db.overview()
    c1,c2,c3,c4=st.columns(4)
    c1.metric('Known CVEs',f"{stats['vulnerabilities']:,}")
    c2.metric('2026 candidates',f"{stats['scoreboard']:,}")
    c3.metric('Historical KEV',f"{stats['historical_kev']:,}")
    c4.metric('Snapshot EPSS coverage',f"{stats['epss_coverage']/stats['scoreboard']:.1%}")
    st.divider()
    a,b=st.columns([1.1,0.9],gap='large')
    with a:
        st.subheader('2026 priority queue')
        rank=db.ranking(12)
        st.dataframe(rank[['priority_rank','cve_id','epss','any_exploit','exploitdb','metasploit','nuclei','poc_github']],hide_index=True,use_container_width=True)
        st.download_button('Download baseline top 500',db.ranking(500)[['cve_id']].to_csv(index=False),'top500.csv','text/csv')
    with b:
        st.subheader('Historical CVE disclosures')
        years=db.published_years()
        years=years[years['year']>=2015]
        fig=px.bar(years,x='year',y='vulnerabilities',color_discrete_sequence=['#1e8c99'])
        fig.update_layout(margin=dict(l=5,r=5,t=5,b=5),height=330)
        st.plotly_chart(fig,use_container_width=True)
        st.caption('Publication year, not the reservation year embedded in a CVE ID.')
    st.info('Model evaluation: historical exploit-first → EPSS captured 11 future KEV additions across 218 selected CVEs in your rolling validation. This cannot be directly compared with the hidden 2026 benchmark.')

elif page=='Ask the Data':
    st.markdown('<div class="hero"><h1>Ask the Data</h1><p>Natural-language analytics grounded in the provided CSVs.</p></div>',unsafe_allow_html=True)
    st.caption('Numbers are computed in DuckDB. Granite (when configured) selects a constrained query and explains returned rows; it cannot execute arbitrary SQL.')
    suggestions=['Which vendor had the most vulnerabilities in 2025?', 'Which vendors have the highest historical KEV rate?', 'What are the most common CWE weakness types?', 'Show the top 20 priority CVEs with public exploit code', 'How many vulnerabilities were published each year?', 'What is CVE-2024-3400?']
    col1,col2,col3=st.columns(3)
    clicked=None
    for i,q in enumerate(suggestions):
        with [col1,col2,col3][i%3]:
            if st.button(q,key=f'example_{i}',use_container_width=True): clicked=q
    if 'messages' not in st.session_state: st.session_state.messages=[]
    for m in st.session_state.messages:
        with st.chat_message(m['role']):
            st.markdown(m['content'])
            if m.get('table') is not None:
                st.dataframe(m['table'],hide_index=True,use_container_width=True)
    prompt=st.chat_input('Ask about CVEs, vendors, KEV, EPSS, weaknesses...')
    if clicked: prompt=clicked
    if prompt:
        st.session_state.messages.append({'role':'user','content':prompt})
        with st.chat_message('user'): st.markdown(prompt)
        with st.chat_message('assistant'):
            with st.spinner('Querying verified data...'):
                try:
                    plan, mode=classify(prompt,use_ai=use_ai)
                    table,note=execute_plan(db,plan)
                    answer=grounded_answer(prompt,table,note,use_ai)
                    st.markdown(answer)
                    if not table.empty:
                        st.dataframe(table,hide_index=True,use_container_width=True)
                    st.caption(f'Engine: {mode} · Operation: {plan["tool"]} · {note}')
                    st.session_state.messages.append({'role':'assistant','content':answer+'\n\n*'+note+'*', 'table':table})
                except Exception as exc:
                    st.error(f'Query failed: {exc}')
    if st.button('Clear chat'):
        st.session_state.messages=[]
        st.rerun()

elif page=='Priority Queue':
    st.markdown('<div class="hero"><h1>Priority Queue</h1><p>Transparent patching priorities based on publicly available exploit indicators and EPSS.</p></div>',unsafe_allow_html=True)
    a,b,c=st.columns([1,1,1])
    with a: n=st.select_slider('Show CVEs',options=[25,50,100,250,500,1000],value=100)
    with b: only=st.checkbox('Public exploit signal only',value=False)
    with c: minimum=st.slider('Minimum EPSS',0.0,1.0,0.0,0.01)
    table=db.ranking(n,minimum,only)
    st.dataframe(table,hide_index=True,use_container_width=True,height=475)
    st.download_button('Export displayed rows',table.to_csv(index=False),'patchradar_queue.csv','text/csv')
    st.markdown('#### Why these CVEs are prioritized')
    st.markdown('A vulnerability is ranked above another if it has any of the four public exploit/detection indicators and the other does not. Within a group, higher EPSS wins. This is a **ranking heuristic**, not a calibrated exploitation probability or proof that a vulnerability has been exploited.')
    if not table.empty:
        counts={k:int(table[k].sum()) for k in ['exploitdb','metasploit','nuclei','poc_github']}
        fig=px.bar(x=list(counts),y=list(counts.values()),labels={'x':'Observed source','y':'CVEs in displayed queue'},color_discrete_sequence=['#1e8c99'])
        st.plotly_chart(fig,use_container_width=True)

elif page=='CVE Investigator':
    st.markdown('<div class="hero"><h1>CVE Investigator</h1><p>Inspect technical evidence, historical signals, and Granite semantic neighbors.</p></div>',unsafe_allow_html=True)
    cve=st.text_input('Enter CVE ID',value='CVE-2026-8037').strip().upper()
    if st.button('Investigate CVE',type='primary'):
        st.session_state['inspect_id']=cve
    chosen=st.session_state.get('inspect_id',cve)
    if chosen:
        try:
            result=db.cve(chosen)
            if result.empty:
                st.warning('CVE was not found in vulnerabilities.csv')
            else:
                row=result.iloc[0]
                st.subheader(chosen)
                st.markdown(str(row.get('description') or 'No description available'))
                m1,m2,m3=st.columns(3)
                m1.metric('Snapshot EPSS',str(row.get('epss') or 'n/a'))
                m2.metric('CVSS v3',str(row.get('cvss3_score') or 'n/a'))
                m3.metric('Historical KEV date',str(row.get('historical_kev_date') or 'Not in supplied KEV'))
                st.markdown('#### Known structured indicators')
                flags=['exploitdb','metasploit','nuclei','poc_github']
                st.dataframe(pd.DataFrame([{'source':f,'value':row.get(f)} for f in flags]),hide_index=True)
                st.caption('Current NIST CVSS and description may postdate the original snapshot; historical KEV catalog ends December 2025.')
                with st.expander('Affected products (current NIST)',expanded=False):
                    st.dataframe(db.cve_products(chosen),hide_index=True)
                with st.expander('Monthly EPSS history (2024–2025)',expanded=False):
                    hist=db.signals_history(chosen)
                    if hist.empty: st.write('No historical signals found.')
                    else:
                        st.line_chart(hist.set_index('month')['epss'])
                        st.dataframe(hist,hide_index=True)
                st.markdown('#### IBM Granite technical similarity')
                st.caption('Optional CPU-intensive feature. It searches historical KEV and top-ranked 2026 candidates, NOT the entire NVD corpus. Semantic similarity is not a predicted exploitation probability.')
                if st.button('Find similar CVEs using Granite embeddings'):
                    with st.spinner('Loading Granite and comparing descriptions...'):
                        try:
                            from semantic import similar_cves
                            matches, model=similar_cves(db,chosen)
                            if matches is None: st.warning('Could not create a similarity query for this CVE.')
                            else:
                                st.success(f'Embedding model: {model}')
                                st.dataframe(matches[['cve_id','cosine_similarity','date_added','description']],hide_index=True,use_container_width=True)
                        except ImportError:
                            st.error('Install optional AI dependencies: pip install -r requirements-ai.txt')
                        except Exception as e:
                            st.error(f'Similarity search failed: {e}')
        except Exception as exc:
            st.error(f'Investigation failed: {exc}')

elif page=='Dataset Explorer':
    st.markdown('<div class="hero"><h1>Data Dictionary</h1><p>Inspect available tables and their column definitions.</p></div>',unsafe_allow_html=True)
    st.dataframe(db.dataset_catalog(),hide_index=True,use_container_width=True)
    st.markdown('### Interpretation and fairness')
    st.markdown('''- `cve_id` is an identifier; the embedded year may differ from the publication year.
- `known_exploited.csv` only includes CISA KEV entries through December 31, 2025.
- `vulnerabilities.csv`, `affected_products.csv`, and `references.csv` are **current NIST exports**; using them as historical prediction features can cause temporal leakage.
- The final 2026 scoreboard gives EPSS and exploit flags at each candidate’s `snapshot_month`.
- Vendor counts include all distinct affected CVEs per vendor; one CVE can contribute to multiple vendors.
- A KEV label means confirmed, cataloged exploitation, not that all other CVEs are safe.''')
