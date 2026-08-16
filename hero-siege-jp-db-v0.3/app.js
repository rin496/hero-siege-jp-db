
let DB;
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const slug=s=>s.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/(^-|-$)/g,'');

function openClass(id){
 const c=DB.classes.find(x=>x.id===id); if(!c)return;
 const skills=DB.skills.filter(s=>s.classId===id);
 $('#dialogContent').innerHTML=`
  <div class="dialog-title"><span class="kicker">CLASS · SEASON 9</span><h2>${esc(c.nameEn)}</h2><p>${esc(c.nameJa)} <small>（暫定表記）</small></p></div>
  <div class="dialog-skills">${skills.map(s=>`<div class="dialog-skill"><b>${esc(s.nameEn)}</b><br><small style="color:#778493">日本語訳: 未確認</small></div>`).join('')}</div>
  <div class="dialog-note">スキル一覧出典: <a href="${esc(c.sourceUrl)}" target="_blank" rel="noopener" style="color:#e9c572">${esc(c.source)}</a></div>`;
 $('#classDialog').showModal();
}
function renderClasses(){
 $('#classGrid').innerHTML=DB.classes.map((c,i)=>`<article class="class-card" data-class="${esc(c.id)}"><span class="num">${String(i+1).padStart(2,'0')}</span><span class="kicker">S9</span><h3>${esc(c.nameEn)}</h3><div class="jp">${esc(c.nameJa)}</div><span class="skill-total">${c.skillCount} skills →</span></article>`).join('');
 $$('.class-card').forEach(x=>x.onclick=()=>openClass(x.dataset.class));
}
function renderSkills(){
 const cid=$('#classFilter').value, q=$('#skillSearch').value.trim().toLowerCase();
 const rows=DB.skills.filter(s=>(!cid||s.classId===cid)&&(!q||s.nameEn.toLowerCase().includes(q)||s.classEn.toLowerCase().includes(q)));
 $('#skillCountLabel').textContent=`${rows.length} / ${DB.skills.length} skills`;
 $('#skillGrid').innerHTML=rows.map(s=>`<article class="skill-card"><span class="pending">翻訳待ち</span><h3>${esc(s.nameEn)}</h3><span class="class">${esc(s.classEn)} / ${esc(s.classJa)}</span></article>`).join('');
}
function tableFor(a){
 if(!a.levels?.length)return '';
 const keys=Object.keys(a.levels[0]).filter(k=>k!=='level');
 const labels={magicFind:'Magic Find',goldFind:'Gold Find',movementSpeed:'移動速度',lifeSteal:'Life Steal',damage:'Damage',allRes:'全耐性',attackDamage:'Attack Damage',stun:'Stun',damageReduction:'Damage減少',duration:'持続'};
 return `<table><thead><tr><th>Lv</th>${keys.map(k=>`<th>${esc(labels[k]||k)}</th>`).join('')}</tr></thead><tbody>${a.levels.map(r=>`<tr><td>${r.level}</td>${keys.map(k=>`<td>${esc(r[k])}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
}
function renderAugments(){
 $('#augmentGrid').innerHTML=DB.augments.map(a=>`<article class="augment"><span class="kicker">S9 · VERIFIED SOURCE</span><h3>${esc(a.nameEn)}</h3><div class="jp">${esc(a.nameJa)}</div><p>${esc(a.summaryJa)}</p><div class="proc">${esc(a.proc)}</div>${tableFor(a)}<a href="${esc(a.sourceUrl)}" target="_blank" rel="noopener">出典を開く ↗</a></article>`).join('');
}
function renderSources(){
 $('#sourceList').innerHTML=DB.sources.map(s=>`<a href="${esc(s.url)}" target="_blank" rel="noopener"><b>${esc(s.name)}</b><span>${esc(s.role)} ↗</span></a>`).join('');
}
function globalSearch(){
 const q=$('#globalSearch').value.trim().toLowerCase(), box=$('#searchResults');
 if(!q){box.classList.remove('show');box.innerHTML='';return;}
 const cs=DB.classes.filter(c=>(c.nameEn+' '+c.nameJa).toLowerCase().includes(q)).slice(0,5);
 const ss=DB.skills.filter(s=>(s.nameEn+' '+s.classEn+' '+s.classJa).toLowerCase().includes(q)).slice(0,8);
 const aa=DB.augments.filter(a=>(a.nameEn+' '+a.nameJa+' '+a.summaryJa).toLowerCase().includes(q)).slice(0,5);
 const hits=[
  ...cs.map(c=>({type:'Class',title:c.nameEn,sub:c.nameJa,action:`class:${c.id}`})),
  ...ss.map(s=>({type:'Skill',title:s.nameEn,sub:s.classEn,action:`skill:${s.classId}`})),
  ...aa.map(a=>({type:'Augment',title:a.nameEn,sub:a.nameJa,action:'augment'}))
 ].slice(0,12);
 box.innerHTML=hits.length?hits.map(h=>`<div class="search-hit" data-action="${esc(h.action)}"><b>${esc(h.title)}</b><small>${esc(h.type)} · ${esc(h.sub)}</small></div>`).join(''):`<div class="search-hit">該当なし</div>`;
 box.classList.add('show');
 $$('.search-hit[data-action]').forEach(x=>x.onclick=()=>{
  const [kind,id]=x.dataset.action.split(':');
  if(kind==='class'||kind==='skill') openClass(id);
  else location.hash='augments';
 });
}
fetch('./data.json').then(r=>r.json()).then(db=>{
 DB=db;
 $('#version').textContent=db.meta.version; $('#classCount').textContent=db.meta.classCount;
 $('#skillCount').textContent=db.meta.skillCount; $('#augmentCount').textContent=db.augments.length;
 $('#verified').textContent=db.meta.lastVerified;
 $('#classFilter').innerHTML='<option value="">全クラス</option>'+db.classes.map(c=>`<option value="${esc(c.id)}">${esc(c.nameEn)}</option>`).join('');
 renderClasses(); renderSkills(); renderAugments(); renderSources();
 $('#classFilter').onchange=renderSkills; $('#skillSearch').oninput=renderSkills; $('#globalSearch').oninput=globalSearch;
 $('#dialogClose').onclick=()=>$('#classDialog').close();
 $('#classDialog').onclick=e=>{if(e.target===$('#classDialog'))$('#classDialog').close()};
});
