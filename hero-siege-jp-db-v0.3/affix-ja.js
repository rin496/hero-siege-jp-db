(()=>{
  const original=window.formatAffix;

  const exact={
    'ATTACKS CAN HIT MULTIPLE ENEMIES':'攻撃が複数の敵にヒットする',
    'PIERCING ATTACK':'攻撃が貫通する',
    'CANNOT BE FROZEN':'凍結しない',
    'DOUBLE JUMP':'二段ジャンプ',
    'MOVEMENT PHASING':'移動中に敵をすり抜ける',
    'HEROBOUND':'ヒーローバウンド',
    'PROJECTILES RETURN TO YOU':'投射物が自分の元に戻る',
    'PROJECTILES ARE FIRED IN RANDOM DIRECTIONS':'投射物がランダムな方向に発射される',
    'MIRRORS YOUR OTHER RING':'もう片方の指輪を複製する'
  };

  const words=[
    ['ALL SKILLS','全スキル'],['LIGHTNING SKILLS','雷スキル'],['FIRE SKILLS','火スキル'],['COLD SKILLS','冷気スキル'],['POISON SKILLS','毒スキル'],['PHYSICAL SKILLS','物理スキル'],['ARCANE SKILLS','アーケインスキル'],['PROJECTILE SKILLS','投射物スキル'],['SUMMON SKILLS','召喚スキル'],['SENTRY SKILLS','セントリースキル'],['EXPLOSION SKILLS','爆発スキル'],
    ['ALL ATTRIBUTES','全属性値'],['STRENGTH','筋力'],['DEXTERITY','器用さ'],['VITALITY','活力'],['ENERGY','エネルギー'],['INTELLIGENCE','知力'],
    ['ALL RESISTANCES','全耐性'],['LIGHTNING RESISTANCE','雷耐性'],['FIRE RESISTANCE','火耐性'],['COLD RESISTANCE','冷気耐性'],['POISON RESISTANCE','毒耐性'],['ARCANE RESISTANCE','アーケイン耐性'],
    ['LIGHTNING SKILL DAMAGE','雷スキルダメージ'],['FIRE SKILL DAMAGE','火スキルダメージ'],['COLD SKILL DAMAGE','冷気スキルダメージ'],['POISON SKILL DAMAGE','毒スキルダメージ'],['ARCANE SKILL DAMAGE','アーケインスキルダメージ'],['MAGIC SKILL DAMAGE','魔法スキルダメージ'],['PROJECTILE DAMAGE','投射物ダメージ'],['SUMMON DAMAGE','召喚ダメージ'],['SENTRY DAMAGE','セントリーダメージ'],['GUARDIAN DAMAGE','ガーディアンダメージ'],['ATTACK DAMAGE','攻撃ダメージ'],['PHYSICAL DAMAGE','物理ダメージ'],['LIGHTNING DAMAGE','雷ダメージ'],['FIRE DAMAGE','火ダメージ'],['COLD DAMAGE','冷気ダメージ'],['POISON DAMAGE','毒ダメージ'],['MAGIC DAMAGE','魔法ダメージ'],['DAMAGE','ダメージ'],
    ['ATTACK SPEED','攻撃速度'],['FASTER CAST RATE','詠唱速度'],['MOVEMENT SPEED','移動速度'],['SKILL HASTE','スキルヘイスト'],['FASTER HIT RECOVERY','ヒットリカバリー速度'],['ATTACK RATING','命中値'],['CRITICAL STRIKE CHANCE','クリティカル率'],['CRITICAL STRIKE DAMAGE','クリティカルダメージ'],['MAGIC FIND','マジックファインド'],['EXTRA GOLD','追加ゴールド'],['EXPERIENCE GAIN','経験値獲得量'],['AREA OF EFFECT','効果範囲'],['PROJECTILE SIZE','投射物サイズ'],['PROJECTILE SPEED','投射物速度'],['ATTACK RANGE','攻撃範囲'],
    ['LIFE','ライフ'],['MANA','マナ'],['ARMOR','アーマー'],['DEFENSE','防御'],['BLOCKING','ブロック'],['SOCKETS','ソケット数']
  ];

  function replaceWords(s){
    for(const [en,ja] of words)s=s.replaceAll(en,ja);
    return s;
  }

  function toJaTemplate(tpl){
    if(!tpl)return tpl;
    if(exact[tpl])return exact[tpl];
    let s=tpl;

    s=s.replace(/^value1 TO (.+)$/,'$1 +value1');
    s=s.replace(/^value1% TO (.+)$/,'$1 +value1%');
    s=s.replace(/^(.+) INCREASED BY value1%$/,'$1が value1% 増加');
    s=s.replace(/^value1% INCREASED (.+)$/,'$1が value1% 増加');
    s=s.replace(/^value1% FASTER (.+)$/,'$1が value1% 高速化');
    s=s.replace(/^(.+) TAKEN REDUCED BY value1%$/,'受ける$1が value1% 軽減');
    s=s.replace(/^(.+) TAKEN REDUCED BY value1$/,'受ける$1が value1 軽減');
    s=s.replace(/^value1% OF (.+) IS ADDED AS (.+)$/,'$1の value1% を$2として追加');
    s=s.replace(/^value1% OF (.+) TAKEN AS (.+)$/,'受ける$1の value1% を$2として受ける');
    s=s.replace(/^value1% CHANCE FOR A DEADLY BLOW$/,'デッドリーブロー確率 value1%');
    s=s.replace(/^value1% CHANCE FOR A CRUSHING BLOW$/,'クラッシングブロー確率 value1%');
    s=s.replace(/^DEADLY BLOW DAMAGE INCREASED BY value1%$/,'デッドリーブローのダメージが value1% 増加');
    s=s.replace(/^value1% CHANCE TO OPEN WOUNDS$/,'オープンウーンズ確率 value1%');
    s=s.replace(/^value1% CHANCE WHEN ATTACKING \[(.+)\] LEVEL value2$/,'攻撃時 value1% の確率で［$1］Lv value2');
    s=s.replace(/^value1% CHANCE WHEN STRIKING \[(.+)\] LEVEL value2$/,'ヒット時 value1% の確率で［$1］Lv value2');
    s=s.replace(/^value1% CHANCE WHEN STRUCK \[(.+)\] LEVEL value2$/,'被弾時 value1% の確率で［$1］Lv value2');
    s=s.replace(/^value1% CHANCE WHEN CASTING \[(.+)\] LEVEL value2$/,'スキル使用時 value1% の確率で［$1］Lv value2');
    s=s.replace(/^value1% CHANCE AFTER EACH KILL \[(.+)\] LEVEL value2$/,'敵撃破時 value1% の確率で［$1］Lv value2');
    s=s.replace(/^value1% CHANCE AFTER BLOCKING \[(.+)\] LEVEL value2$/,'ブロック時 value1% の確率で［$1］Lv value2');
    s=s.replace(/^REPLENISH LIFE value1%$/,'ライフを value1% 回復');
    s=s.replace(/^REPLENISH MANA value1%$/,'マナを value1% 回復');
    s=s.replace(/^value1 LIFE AFTER EACH KILL$/,'敵撃破時にライフ +value1');
    s=s.replace(/^value1 MANA AFTER EACH KILL$/,'敵撃破時にマナ +value1');
    s=s.replace(/^value1 LIFE PER SECOND$/,'毎秒ライフ +value1');
    s=s.replace(/^value1 MANA PER SECOND$/,'毎秒マナ +value1');
    s=s.replace(/^value1% LIFE STOLEN PER HIT$/,'ライフリーチ value1%');
    s=s.replace(/^value1% MANA STOLEN PER HIT$/,'マナリーチ value1%');
    s=s.replace(/^value1% TO ALL ENEMY RESISTANCES$/,'敵の全耐性に value1%');
    s=s.replace(/^value1% TO ENEMY (.+) RESISTANCE$/,'敵の$1耐性に value1%');
    s=s.replace(/^value1% OF TARGET DEFENSE IGNORED$/,'対象の防御を value1% 無視');
    s=s.replace(/^(.+) AURA LEVEL value1(?: \(HOLDER ONLY\))?$/,'$1オーラ Lv value1');
    s=s.replace(/^value1 RANDOM SKILL ELEMENT$/,'ランダムなスキル属性 +value1');
    s=s.replace(/^value1 RANDOM UNHOLY AFFIX$/,'ランダムなUnholy Affix +value1');
    s=s.replace(/^SOCKETS \(value1\)$/,'ソケット数 value1');
    s=s.replace(/^EFFECT DURATION value1 SECONDS$/,'効果時間 value1秒');
    s=s.replace(/^MANA COSTS DECREASED BY value1%$/,'マナコストが value1% 減少');
    s=s.replace(/^POISON LENGTH REDUCED BY value1%$/,'毒の持続時間が value1% 短縮');
    s=s.replace(/^HALF FREEZE DURATION$/,'凍結時間が半分になる');

    s=replaceWords(s);
    return s;
  }

  window.formatAffix=function(id,values){
    const tpl=(window.AFFIX_MAP&&AFFIX_MAP[id])||id;
    const jaTpl=toJaTemplate(tpl);
    if(values==null||!Array.isArray(values)||values.length===0)return {text:jaTpl,roll:''};
    if(jaTpl.includes('value2')){
      const text=jaTpl.replaceAll('value1',String(values[0]??'?')).replaceAll('value2',String(values[1]??'?'));
      return {text,roll:''};
    }
    if(values.length===1)return {text:jaTpl.replaceAll('value1',String(values[0])),roll:''};
    const text=jaTpl.replaceAll('value1','X');
    return {text,roll:`${values[0]}–${values[1]}`};
  };
})();
