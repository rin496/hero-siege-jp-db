let DB, ITEMS=[], AFFIX_MAP={};
let itemDisplayLimit=120;
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const cap=s=>s?String(s).charAt(0).toUpperCase()+String(s).slice(1):'';
const SLOT_LABELS={weapon:'Weapon',body_armor:'Body Armor',helmet:'Helmet',boots:'Boots',gloves:'Gloves',belt:'Belt',ring:'Ring',amulet:'Amulet',charm:'Charm',shield:'Shield'};

async function fetchJSON(path){const r=await fetch(path,{cache:'no-store'});if(!r.ok)throw new Error(`${path}: ${r.status}`);return r.json()}
async function loadUniqueData(){
 const manifest=await fetchJSON('./unique-manifest.json');
 const [parts,affixParts]=await Promise.all([
  Promise.all(manifest.files.map(f=>fetchJSON('./'+f))),
  Promise.all((manifest.affixFiles||[]).map(f=>fetchJSON('./'+f)))
 ]);
 AFFIX_MAP=Object.assign({},...affixParts);
 const items=parts.flat().map(r=>({
  refId:r[0],internalId:r[1],nameEn:r[2],nameJa:r[3]||'',rarity:cap(r[4]),slotKey:r[5],slot:SLOT_LABELS[r[5]]||r[5],
  subclasses:r[6]||[],handedness:r[7]||[],requiredLevel:r[8],dropAreas:r[9]||[],dropRate:r[10],affixes:r[11]||[]
 }));
 if(manifest.itemCount&&items.length!==manifest.itemCount)console.warn(`manifest count ${manifest.itemCount} != loaded ${items.length}`);
 return items;
}
function formatAffix(id,values){
 const tpl=AFFIX_MAP[id]||id;
 if(values==null||!Array.isArray(values)||values.length===0)return {text:tpl,roll:''};
 if(tpl.includes('value2')){
  let text=tpl.replaceAll('value1',String(values[0]??'?')).replaceAll('value2',String(values[1]??'?'));
  return {text,roll:''};
 }
 if(values.length===1)return {text:tpl.replaceAll('value1',String(values[0])),roll:''};
 const text=tpl.replaceAll('value1','X');
 return {text,roll:`${values[0]}–${values[1]}`};
}
function filteredItems(){
 const q=$('#itemSearch').value.trim().toLowerCase(),slot=$('#slotFilter').value,rarity=$('#rarityFilter').value,wt=$('#weaponFilter').value;
 return ITEMS.filter(i=>{
  const hay=[i.nameEn,i.nameJa,i.refId,i.internalId,i.slot,...i.subclasses,...i.handedness].filter(Boolean).join(' ').toLowerCase();
  return(!q||hay.includes(q))&&(!slot||i.slotKey===slot)&&(!rarity||i.rarity===rarity)&&(!wt||i.subclasses.includes(wt));
 });
}
function openItem(id){
 const i=ITEMS.find(x=>x.refId===id);if(!i)return;
 const rows=[['英語名',i.nameEn],['日本語',i.nameJa||'（ゲーム翻訳未確認）'],['レアリティ',i.rarity],['装備部位',i.slot],['武器種',i.subclasses.join(', ')||'—'],['持ち方',i.handedness.join(', ')||'—'],['必要Lv',i.requiredLevel??'—'],['ゲーム内部ID',i.internalId||'—'],['参照DB ID',i.refId]];
 const affixes=i.affixes.map(([aid,vals])=>{const f=formatAffix(aid,vals);return `<div class="affix-row"><div><b>${esc(f.text)}</b><code>${esc(aid)}</code></div>${f.roll?`<span class="roll-range">Roll ${esc(f.roll)}</span>`:''}</div>`}).join('');
 const drops=i.dropAreas.length?i.dropAreas.join(', '):'—';
 const dropRate=i.dropRate==null?'—':`${i.dropRate}（参照DBの内部値）`;
 $('#itemDialogContent').innerHTML=`<div class="dialog-title"><span class="kicker">NAMED UNIQUE · ${esc(i.rarity.toUpperCase())}</span><h2>${esc(i.nameEn)}</h2><p>${esc(i.nameJa||'ゲーム翻訳未確認')}</p></div><div class="item-detail-table">${rows.map(([k,v])=>`<div><span>${esc(k)}</span><b>${esc(v)}</b></div>`).join('')}</div><h3>Affixes / Roll</h3><div class="affix-list">${affixes||'<p>Affixデータなし</p>'}</div><div class="item-detail-table"><div><span>Drop Area</span><b>${esc(drops)}</b></div><div><span>Drop Rate</span><b>${esc(dropRate)}</b></div></div><div class="game-source-box"><b>Identity / 日本語: Hero Siege game files</b><span>translationsItem.csv を一次ソースとして照合</span></div><div class="game-source-box"><b>性能・必要Lv・ドロップ: HeroSiegeDB items.php</b><span>二次資料として照合。ゲームファイルで未確認の値を含みます。</span></div>`;
 $('#itemDialog').showModal();
}
function renderItems(reset=false){
 if(reset)itemDisplayLimit=120;const rows=filteredItems(),shown=rows.slice(0,itemDisplayLimit);
 $('#itemCountLabel').textContent=`${shown.length} 件表示 / 該当 ${rows.length} 件 / 全 ${ITEMS.length} 件`;
 $('#itemGrid').innerHTML=shown.map(i=>`<article class="item-card" data-item="${esc(i.refId)}"><div class="item-top"><span class="rarity ${i.rarity.toLowerCase()}">${esc(i.rarity)}</span><span>${esc(i.slot)}</span></div><h3>${esc(i.nameEn)}</h3><div class="jp">${esc(i.nameJa||'ゲーム翻訳未確認')}</div><div class="item-meta">${i.subclasses.length?`<span>${esc(i.subclasses.join(', '))}</span>`:''}${i.requiredLevel!=null?`<span>Lv ${esc(i.requiredLevel)}</span>`:''}<code>${esc(i.internalId||i.refId)}</code></div></article>`).join('');
 $$('.item-card').forEach(x=>x.onclick=()=>openItem(x.dataset.item));$('#loadMoreItems').style.display=shown.length<rows.length?'block':'none';
}
function initItemFilters(){
 const slots=[...new Set(ITEMS.map(i=>i.slotKey))].sort(),wtypes=[...new Set(ITEMS.flatMap(i=>i.subclasses))].sort();
 $('#slotFilter').innerHTML='<option value="">全装備部位</option>'+slots.map(x=>`<option value="${esc(x)}">${esc(SLOT_LABELS[x]||x)}</option>`).join('');
 $('#weaponFilter').innerHTML='<option value="">全武器種</option>'+wtypes.map(x=>`<option value="${esc(x)}">${esc(cap(x))}</option>`).join('');
 $('#itemCount').textContent=ITEMS.length;$('#uniqueCount').textContent=ITEMS.length;
 $('#itemSourceStatus').className='source-banner ok';
 $('#itemSourceStatus').innerHTML=`<b>Named Unique ${ITEMS.length}件</b><span>一次: Hero Siege game files（識別・日本語） / 性能: HeroSiegeDB items.php（二次照合）</span>`;
 renderItems(true);
}
function openClass(id){const c=DB.classes.find(x=>x.id===id);if(!c)return;const skills=DB.skills.filter(s=>s.classId===id);$('#dialogContent').innerHTML=`<div class="dialog-title"><span class="kicker">CLASS · SEASON 9</span><h2>${esc(c.nameEn)}</h2><p>${esc(c.nameJa)}</p></div><div class="dialog-skills">${skills.map(s=>`<div class="dialog-skill"><b>${esc(s.nameEn)}</b><br><small style="color:#778493">日本語訳: 未確認</small></div>`).join('')}</div>`;$('#classDialog').showModal()}
function renderClasses(){$('#classGrid').innerHTML=DB.classes.map((c,i)=>`<article class="class-card" data-class="${esc(c.id)}"><span class="num">${String(i+1).padStart(2,'0')}</span><span class="kicker">S9</span><h3>${esc(c.nameEn)}</h3><div class="jp">${esc(c.nameJa)}</div><span class="skill-total">${c.skillCount} skills →</span></article>`).join('');$$('.class-card').forEach(x=>x.onclick=()=>openClass(x.dataset.class))}
function renderSkills(){const cid=$('#classFilter').value,q=$('#skillSearch').value.trim().toLowerCase();const rows=DB.skills.filter(s=>(!cid||s.classId===cid)&&(!q||s.nameEn.toLowerCase().includes(q)||s.classEn.toLowerCase().includes(q)));$('#skillCountLabel').textContent=`${rows.length} / ${DB.skills.length} skills`;$('#skillGrid').innerHTML=rows.map(s=>`<article class="skill-card"><span class="pending">翻訳待ち</span><h3>${esc(s.nameEn)}</h3><span class="class">${esc(s.classEn)} / ${esc(s.classJa)}</span></article>`).join('')}
function tableFor(a){if(!a.levels?.length)return '';const keys=Object.keys(a.levels[0]).filter(k=>k!=='level');return `<table><thead><tr><th>Lv</th>${keys.map(k=>`<th>${esc(k)}</th>`).join('')}</tr></thead><tbody>${a.levels.map(r=>`<tr><td>${r.level}</td>${keys.map(k=>`<td>${esc(r[k])}</td>`).join('')}</tr>`).join('')}</tbody></table>`}
function renderAugments(){$('#augmentGrid').innerHTML=DB.augments.map(a=>`<article class="augment"><span class="kicker">S9</span><h3>${esc(a.nameEn)}</h3><div class="jp">${esc(a.nameJa)}</div><p>${esc(a.summaryJa)}</p><div class="proc">${esc(a.proc)}</div>${tableFor(a)}</article>`).join('')}
function globalSearch(){const q=$('#globalSearch').value.trim().toLowerCase(),box=$('#searchResults');if(!q){box.classList.remove('show');box.innerHTML='';return}const ii=ITEMS.filter(i=>[i.nameEn,i.nameJa,i.internalId,i.refId].join(' ').toLowerCase().includes(q)).slice(0,8),cs=DB.classes.filter(c=>(c.nameEn+' '+c.nameJa).toLowerCase().includes(q)).slice(0,4),ss=DB.skills.filter(s=>(s.nameEn+' '+s.classEn).toLowerCase().includes(q)).slice(0,5);const hits=[...ii.map(i=>({type:'Item',title:i.nameEn,sub:i.nameJa||i.slot,action:`item:${i.refId}`})),...cs.map(c=>({type:'Class',title:c.nameEn,sub:c.nameJa,action:`class:${c.id}`})),...ss.map(s=>({type:'Skill',title:s.nameEn,sub:s.classEn,action:`skill:${s.classId}`}))].slice(0,12);box.innerHTML=hits.length?hits.map(h=>`<div class="search-hit" data-action="${esc(h.action)}"><b>${esc(h.title)}</b><small>${esc(h.type)} · ${esc(h.sub)}</small></div>`).join(''):'<div class="search-hit">該当なし</div>';box.classList.add('show');$$('.search-hit[data-action]').forEach(x=>x.onclick=()=>{const p=x.dataset.action.indexOf(':'),kind=x.dataset.action.slice(0,p),id=x.dataset.action.slice(p+1);if(kind==='item')openItem(id);else openClass(id)})}
Promise.all([fetch('./data.json').then(r=>r.json()),loadUniqueData()]).then(([db,itemRows])=>{DB=db;ITEMS=itemRows;$('#classCount').textContent=db.meta.classCount;$('#classFilter').innerHTML='<option value="">全クラス</option>'+db.classes.map(c=>`<option value="${esc(c.id)}">${esc(c.nameEn)}</option>`).join('');initItemFilters();renderClasses();renderSkills();renderAugments();$('#classFilter').onchange=renderSkills;$('#skillSearch').oninput=renderSkills;$('#globalSearch').oninput=globalSearch;['#itemSearch','#slotFilter','#rarityFilter','#weaponFilter'].forEach(sel=>$(sel).addEventListener(sel==='#itemSearch'?'input':'change',()=>renderItems(true)));$('#loadMoreItems').onclick=()=>{itemDisplayLimit+=120;renderItems(false)};$('#itemDialogClose').onclick=()=>$('#itemDialog').close();$('#itemDialog').onclick=e=>{if(e.target===$('#itemDialog'))$('#itemDialog').close()};$('#dialogClose').onclick=()=>$('#classDialog').close();$('#classDialog').onclick=e=>{if(e.target===$('#classDialog'))$('#classDialog').close()}}).catch(err=>{console.error(err);$('#itemSourceStatus').className='source-banner error';$('#itemSourceStatus').innerHTML='<b>Uniqueデータを読み込めません</b><span>unique-manifest.json / chunk files を確認してください。</span>'});