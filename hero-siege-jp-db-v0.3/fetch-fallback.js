(()=>{
  const nativeFetch=window.fetch.bind(window);
  const RAW_BASE='https://raw.githubusercontent.com/rin496/hero-siege-jp-db/main/hero-siege-jp-db-v0.3/';

  async function githubFallback(input,init,reason){
    try{
      const url=new URL(typeof input==='string'?input:input.url,location.href);
      if(url.origin!==location.origin || !url.pathname.endsWith('.json'))return null;
      const file=url.pathname.split('/').filter(Boolean).pop();
      if(!file)return null;
      const fallback=await nativeFetch(RAW_BASE+encodeURIComponent(file),{...(init||{}),cache:'no-store'});
      if(fallback.ok){
        console.warn('[Hero Siege DB] using GitHub raw fallback:',file,reason||'local fetch failed');
        return fallback;
      }
      console.warn('[Hero Siege DB] GitHub raw fallback HTTP error:',file,fallback.status);
    }catch(e){
      console.warn('[Hero Siege DB] fallback fetch failed',e);
    }
    return null;
  }

  window.fetch=async function(input,init){
    let response;
    try{
      response=await nativeFetch(input,init);
      if(response.ok)return response;
    }catch(e){
      const fallback=await githubFallback(input,init,e?.message||String(e));
      if(fallback)return fallback;
      throw e;
    }

    const fallback=await githubFallback(input,init,`HTTP ${response.status}`);
    return fallback||response;
  };
})();
