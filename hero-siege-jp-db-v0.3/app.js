let DB, ITEMS=[];
let itemDisplayLimit=120;
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function classifyItem(section,id){
 const s=(section||'').toLowerCase(); let slot='Other',weaponType='';
 const rarity=s.includes('unique')?'Unique':'Normal';
 if(s.startsWith('normal axes')){slot='Weapon';weaponType='Axe'}
 else if(s.startsWith('normal maces')){slot='Weapon';weaponType='Mace'}
 else if(s.startsWith('normal daggers')){slot='Weapon';weaponType='Dagger'}
 else if(s.startsWith('normal swords')){slot='Weapon';weaponType='Sword'}
 else if(s.includes('weapon_melee')){slot='Weapon';weaponType='Melee'}
 else if(s.includes('weapon_throwing')){slot='Weapon';weaponType='Throwing'}
 else if(s.includes('weapon_spell')){slot='Weapon';weaponType='Spell'}
 else if(s.includes('weapon_bow')){slot='Weapon';weaponType='Bow'}
 else if(s.includes('weapon_claw')){slot='Weapon';weaponType='Claw'}
 else if(s.includes('weapon_polearm')||s.includes('weapon_spear')){slot='Weapon';weaponType='Polearm / Spear'}
 else if(s.includes('weapon_gun')){slot='Weapon';weaponType='Gun'}
 else if(s.includes('weapon_chainsaw')){slot='Weapon';weaponType='Chainsaw'}
 else if(s.includes('weapon_flask')){slot='Weapon';weaponType='Flask'}
 else if(s.includes('weapon_universal')){slot='Weapon';weaponType='Universal'}
 else if(s.startsWith('armors')) slot='Armor';
 else if(s.startsWith('helms')) slot='Helm';
 else if(s.startsWith('gloves')) slot='Gloves';
 else if(s.startsWith('boots')) slot='Boots';
 else if(s.startsWith('amulets')) slot='Amulet';
 else if(s.startsWith('charms')) slot='Charm';
 else if(s.startsWith('shields')) slot='Shield';
 else if(s.startsWith('rings')) slot='Ring';
 else if(s.startsWith('belts')) slot='Belt';
 return {slot,weaponType,rarity};
}

function parseItemCsv(text){
 const lines=text.replace(/^\uFEFF/,'').split(/\r?\n/), out=[];
 let section='',sectionIndex=-1;
 for(const line of lines){
  if(!line) continue;
  const p=line.split('|'), first=(p[0]||'').trim();
  if(first.startsWith('[')&&first.endsWith(']')){section=first.slice(1,-1);sectionIndex++;continue}
  if(sectionIndex<0||sectionIndex>39||!first||first.startsWith('lore_')||p.length<12||!(p[1]||'').trim()) continue;
  const c=classifyItem(section,first);
  out.push({id:first,nameEn:(p[1]||'').trim(),nameJa:(p[6]||'').trim(),section,...c});
 }
 return out;
}

function filteredItems(){
 const q=$('#itemSearch').value.trim().toLowerCase(),slot=$('#slotFilter').value,rarity=$('#rarityFilter').value,wt=$('#weaponFilter').value;
 return ITEMS.filter(i=>{const hay=[i.nameEn,i.nameJa,i.id,i.section,i.slot,i.weaponType].filter(Boolean).join(' ').toLowerCase();return(!q||hay.includes(q))&&(!slot||i.slot===slot)&&(!rarity||i.rarity===rarity)&&(!wt||i.weaponType===wt)});
}
function openItem(id){
 const i=ITEMS.find(x=>x.id===id);if(!i)return;
 const rows=[['英語名',i.nameEn],['日本語',i.nameJa||'—'],['内部ID',i.id],['装備部位',i.slot],['レアリティ',i.rarity],['武器種',i.weaponType||'—'],['翻訳セクション',i.section]];
 $('#itemDialogContent').innerHTML=`<div class="dialog-title"><span class="kicker">ITEM · DIRECT GAME FILE</span><h2>${esc(i.nameEn)}</h2><p>${esc(i.nameJa||'日本語名なし')}</p></div><div class="item-detail-table">${rows.map(([k,v])=>`<div><span>${esc(k)}</span><b>${esc(v)}</b></div>`).join('')}</div><div class="game-source-box"><b>Source: Hero Siege game files</b><span>translationsItem.csv · internal id / en / ja</span></div><p class="performance-pending">性能値・要求Lv・固有効果はゲームファイルから直接取得できる方法を解析中です。第三者サイトの数値は補完していません。</p>`;
 $('#itemDialog').showModal();
}
function renderItems(reset=false){
 if(reset)itemDisplayLimit=120;const rows=filteredItems(),shown=rows.slice(0,itemDisplayLimit);
 $('#itemCountLabel').textContent=`${shown.length} 件表示 / 該当 ${rows.length} 件 / 全 ${ITEMS.length} 件`;
 $('#itemGrid').innerHTML=shown.map(i=>`<article class="item-card" data-item="${esc(i.id)}"><div class="item-top"><span class="rarity ${i.rarity.toLowerCase()}">${esc(i.rarity)}</span><span>${esc(i.slot)}</span></div><h3>${esc(i.nameEn)}</h3><div class="jp">${esc(i.nameJa||'—')}</div><div class="item-meta">${i.weaponType?`<span>${esc(i.weaponType)}</span>`:''}<code>${esc(i.id)}</code></div></article>`).join('');
 $$('.item-card').forEach(x=>x.onclick=()=>openItem(x.dataset.item));
 $('#loadMoreItems').style.display=shown.length<rows.length?'block':'none';
}
function initItemFilters(){
 const slots=[...new Set(ITEMS.map(i=>i.slot))].sort(),wtypes=[...new Set(ITEMS.map(i=>i.weaponType).filter(Boolean))].sort();
 $('#slotFilter').innerHTML='<option value="">全装備部位</option>'+slots.map(x=>`<option value="${esc(x)}">${esc(x)}</option>`).join('');
 $('#weaponFilter').innerHTML='<option value="">全武器種</option>'+wtypes.map(x=>`<option value="${esc(x)}">${esc(x)}</option>`).join('');
 $('#itemCount').textContent=ITEMS.length;$('#uniqueCount').textContent=ITEMS.filter(i=>i.rarity==='Unique').length;
 $('#itemSourceStatus').className='source-banner ok';$('#itemSourceStatus').innerHTML='<b>一次ソース: Hero Siege ゲームファイル</b><span>translationsItem.csv を直接解析中 · 第三者DB不使用</span>';
 renderItems(true);
}

function openClass(id){
 const c=DB.classes.find(x=>x.id===id); if(!c)return;
 const skills=DB.skills.filter(s=>s.classId===id);
 $('#dialogContent').innerHTML=`<div class="dialog-title"><span class="kicker">CLASS · SEASON 9</span><h2>${esc(c.nameEn)}</h2><p>${esc(c.nameJa)}</p></div><div class="dialog-skills">${skills.map(s=>`<div class="dialog-skill"><b>${esc(s.nameEn)}</b><br><small style="color:#778493">日本語訳: 未確認</small></div>`).join('')}</div>`;
 $('#classDialog').showModal();
}
function renderClasses(){
 $('#classGrid').innerHTML=DB.classes.map((c,i)=>`<article class="class-card" data-class="${esc(c.id)}"><span class="num">${String(i+1).padStart(2,'0')}</span><span class="kicker">S9</span><h3>${esc(c.nameEn)}</h3><div class="jp">${esc(c.nameJa)}</div><span class="skill-total">${c.skillCount} skills →</span></article>`).join('');
 $$('.class-card').forEach(x=>x.onclick=()=>openClass(x.dataset.class));
}
function renderSkills(){
 const cid=$('#classFilter').value,q=$('#skillSearch').value.trim().toLowerCase();
 const rows=DB.skills.filter(s=>(!cid||s.classId===cid)&&(!q||s.nameEn.toLowerCase().includes(q)||s.classEn.toLowerCase().includes(q)));
 $('#skillCountLabel').textContent=`${rows.length} / ${DB.skills.length} skills`;
 $('#skillGrid').innerHTML=rows.map(s=>`<article class="skill-card"><span class="pending">翻訳待ち</span><h3>${esc(s.nameEn)}</h3><span class="class">${esc(s.classEn)} / ${esc(s.classJa)}</span></article>`).join('');
}
function tableFor(a){if(!a.levels?.length)return '';const keys=Object.keys(a.levels[0]).filter(k=>k!=='level');return `<table><thead><tr><th>Lv</th>${keys.map(k=>`<th>${esc(k)}</th>`).join('')}</tr></thead><tbody>${a.levels.map(r=>`<tr><td>${r.level}</td>${keys.map(k=>`<td>${esc(r[k])}</td>`).join('')}</tr>`).join('')}</tbody></table>`}
function renderAugments(){
 $('#augmentGrid').innerHTML=DB.augments.map(a=>`<article class="augment"><span class="kicker">S9</span><h3>${esc(a.nameEn)}</h3><div class="jp">${esc(a.nameJa)}</div><p>${esc(a.summaryJa)}</p><div class="proc">${esc(a.proc)}</div>${tableFor(a)}</article>`).join('');
}
function globalSearch(){
 const q=$('#globalSearch').value.trim().toLowerCase(),box=$('#searchResults');if(!q){box.classList.remove('show');box.innerHTML='';return}
 const ii=ITEMS.filter(i=>(i.nameEn+' '+i.nameJa+' '+i.id).toLowerCase().includes(q)).slice(0,8),cs=DB.classes.filter(c=>(c.nameEn+' '+c.nameJa).toLowerCase().includes(q)).slice(0,4),ss=DB.skills.filter(s=>(s.nameEn+' '+s.classEn).toLowerCase().includes(q)).slice(0,5);
 const hits=[...ii.map(i=>({type:'Item',title:i.nameEn,sub:i.nameJa||i.slot,action:`item:${i.id}`})),...cs.map(c=>({type:'Class',title:c.nameEn,sub:c.nameJa,action:`class:${c.id}`})),...ss.map(s=>({type:'Skill',title:s.nameEn,sub:s.classEn,action:`skill:${s.classId}`}))].slice(0,12);
 box.innerHTML=hits.length?hits.map(h=>`<div class="search-hit" data-action="${esc(h.action)}"><b>${esc(h.title)}</b><small>${esc(h.type)} · ${esc(h.sub)}</small></div>`).join(''):'<div class="search-hit">該当なし</div>';box.classList.add('show');
 $$('.search-hit[data-action]').forEach(x=>x.onclick=()=>{const [kind,id]=x.dataset.action.split(':');if(kind==='item')openItem(id);else openClass(id)});
}

Promise.all([fetch('./data.json').then(r=>r.json()),fetch('./translationsItem.csv').then(r=>{if(!r.ok)throw new Error('translationsItem.csv not found');return r.text()})]).then(([db,csv])=>{
 DB=db;ITEMS=parseItemCsv(csv);
 $('#classCount').textContent=db.meta.classCount;
 $('#classFilter').innerHTML='<option value="">全クラス</option>'+db.classes.map(c=>`<option value="${esc(c.id)}">${esc(c.nameEn)}</option>`).join('');
 initItemFilters();renderClasses();renderSkills();renderAugments();
 $('#classFilter').onchange=renderSkills;$('#skillSearch').oninput=renderSkills;$('#globalSearch').oninput=globalSearch;
 ['#itemSearch','#slotFilter','#rarityFilter','#weaponFilter'].forEach(sel=>$(sel).addEventListener(sel==='#itemSearch'?'input':'change',()=>renderItems(true)));
 $('#loadMoreItems').onclick=()=>{itemDisplayLimit+=120;renderItems(false)};
 $('#itemDialogClose').onclick=()=>$('#itemDialog').close();$('#itemDialog').onclick=e=>{if(e.target===$('#itemDialog'))$('#itemDialog').close()};
 $('#dialogClose').onclick=()=>$('#classDialog').close();$('#classDialog').onclick=e=>{if(e.target===$('#classDialog'))$('#classDialog').close()};
}).catch(err=>{console.error(err);$('#itemSourceStatus').className='source-banner error';$('#itemSourceStatus').innerHTML='<b>translationsItem.csv を読み込めません</b><span>GitHubにゲームファイル由来CSVを配置してください。</span>'});