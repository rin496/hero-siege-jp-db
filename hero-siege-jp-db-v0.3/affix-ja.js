(()=>{
  const exact={
    'ATTACKS CAN HIT MULTIPLE ENEMIES':'攻撃が複数の敵に当たる',
    'PIERCING ATTACK':'貫通攻撃','CANNOT BE FROZEN':'凍結不可','DOUBLE JUMP':'ダブルジャンプ',
    'MOVEMENT PHASING':'移動フェージング','HEROBOUND':'ヒーローバウンド',
    'PROJECTILES RETURN TO YOU':'投射物が自分の元へ戻る','PROJECTILES ARE FIRED IN RANDOM DIRECTIONS':'投射物がランダムな方向に発射される',
    'MIRRORS YOUR OTHER RING':'他の指輪を反映'
  };
  function fallback(tpl){
    if(!tpl)return tpl;if(exact[tpl])return exact[tpl];let s=tpl;
    s=s.replace(/^value1 TO (.+)$/,'$1 +value1').replace(/^value1% TO (.+)$/,'$1 +value1%');
    s=s.replace(/^(.+) INCREASED BY value1%$/,'$1が value1% 増加').replace(/^value1% INCREASED (.+)$/,'$1が value1% 増加');
    s=s.replace(/^value1% FASTER (.+)$/,'$1が value1% 高速化').replace(/^(.+) TAKEN REDUCED BY value1%$/,'受ける$1が value1% 軽減');
    s=s.replace(/^value1% CHANCE FOR A DEADLY BLOW$/,'致命的な一撃のチャンス value1%').replace(/^value1% CHANCE FOR A CRUSHING BLOW$/,'打撃力増加のチャンス value1%');
    s=s.replace(/^value1% CHANCE WHEN ATTACKING \[(.+)\] LEVEL value2$/,'攻撃時 value1% の確率で［$1］Lv value2');
    s=s.replace(/^value1% CHANCE WHEN STRIKING \[(.+)\] LEVEL value2$/,'ヒット時 value1% の確率で［$1］Lv value2');
    s=s.replace(/^value1% CHANCE WHEN STRUCK \[(.+)\] LEVEL value2$/,'被弾時 value1% の確率で［$1］Lv value2');
    s=s.replace(/^value1% CHANCE WHEN CASTING \[(.+)\] LEVEL value2$/,'スキル使用時 value1% の確率で［$1］Lv value2');
    s=s.replace(/^value1% CHANCE AFTER EACH KILL \[(.+)\] LEVEL value2$/,'敵撃破時 value1% の確率で［$1］Lv value2');
    s=s.replace(/^value1% CHANCE AFTER BLOCKING \[(.+)\] LEVEL value2$/,'ブロック時 value1% の確率で［$1］Lv value2');
    s=s.replace(/^REPLENISH LIFE value1%$/,'生命力の回復 value1%').replace(/^REPLENISH MANA value1%$/,'マナの回復 value1%');
    s=s.replace(/^value1 LIFE AFTER EACH KILL$/,'キル後の生命回復 +value1').replace(/^value1 MANA AFTER EACH KILL$/,'キル後のマナ回復 +value1');
    s=s.replace(/^SOCKETS \(value1\)$/,'ソケット数 value1').replace(/^EFFECT DURATION value1 SECONDS$/,'効果持続時間 value1秒');
    return s;
  }
  function unitFor(tpl){return /value1%/.test(tpl||'')?'%':''}
  window.formatAffix=function(id,values){
    const tpl=(window.AFFIX_MAP&&AFFIX_MAP[id])||id;
    const official=(window.ATTRIBUTE_JA&&ATTRIBUTE_JA[id])||'';
    if(official && !tpl.includes('value2')){
      if(values==null||!Array.isArray(values)||values.length===0)return {text:official,roll:''};
      const unit=unitFor(tpl);
      if(values.length===1)return {text:`${official}: ${values[0]}${unit}`,roll:''};
      return {text:`${official}: X${unit}`,roll:`${values[0]}–${values[1]}`};
    }
    const ja=fallback(tpl);
    if(values==null||!Array.isArray(values)||values.length===0)return {text:ja,roll:''};
    if(ja.includes('value2'))return {text:ja.replaceAll('value1',String(values[0]??'?')).replaceAll('value2',String(values[1]??'?')),roll:''};
    if(values.length===1)return {text:ja.replaceAll('value1',String(values[0])),roll:''};
    return {text:ja.replaceAll('value1','X'),roll:`${values[0]}–${values[1]}`};
  };
})();
