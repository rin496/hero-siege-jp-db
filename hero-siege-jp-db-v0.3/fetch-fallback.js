(()=>{
  const nativeFetch=window.fetch.bind(window);
  const RAW_BASE='https://raw.githubusercontent.com/rin496/hero-siege-jp-db/main/hero-siege-jp-db-v0.3/';
  window.fetch=async function(input,init){
    const response=await nativeFetch(input,init);
    if(response.ok)return response;
    try{
      const url=new URL(typeof input==='string'?input:input.url,location.href);
      if(url.origin===location.origin && url.pathname.endsWith('.json')){
        const file=url.pathname.split('/').filter(Boolean).pop();
        if(file){
          const fallback=await nativeFetch(RAW_BASE+encodeURIComponent(file),{cache:'no-store'});
          if(fallback.ok){
            console.warn('[Hero Siege DB] local JSON failed; using GitHub raw fallback:',file,response.status);
            return fallback;
          }
        }
      }
    }catch(e){console.warn('[Hero Siege DB] fallback fetch failed',e)}
    return response;
  };
})();
