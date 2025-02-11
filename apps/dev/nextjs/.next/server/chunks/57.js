"use strict";exports.id=57,exports.ids=[57],exports.modules={29057:(e,t,r)=>{r.d(t,{I8:()=>tX});var i,n,a,o,s,c,l={};r.r(l),r.d(l,{parse:()=>ef,serialize:()=>ew});var u=function(e,t,r,i,n){if("m"===i)throw TypeError("Private method is not writable");if("a"===i&&!n)throw TypeError("Private accessor was defined without a setter");if("function"==typeof t?e!==t||!n:!t.has(e))throw TypeError("Cannot write private member to an object whose class did not declare it");return"a"===i?n.call(e,r):n?n.value=r:t.set(e,r),r},d=function(e,t,r,i){if("a"===r&&!i)throw TypeError("Private accessor was defined without a getter");if("function"==typeof t?e!==t||!i:!t.has(e))throw TypeError("Cannot read private member from an object whose class did not declare it");return"m"===r?i:"a"===r?i.call(e):i?i.value:t.get(e)};function p(e){let t=e?"__Secure-":"";return{sessionToken:{name:`${t}authjs.session-token`,options:{httpOnly:!0,sameSite:"lax",path:"/",secure:e}},callbackUrl:{name:`${t}authjs.callback-url`,options:{httpOnly:!0,sameSite:"lax",path:"/",secure:e}},csrfToken:{name:`${e?"__Host-":""}authjs.csrf-token`,options:{httpOnly:!0,sameSite:"lax",path:"/",secure:e}},pkceCodeVerifier:{name:`${t}authjs.pkce.code_verifier`,options:{httpOnly:!0,sameSite:"lax",path:"/",secure:e,maxAge:900}},state:{name:`${t}authjs.state`,options:{httpOnly:!0,sameSite:"lax",path:"/",secure:e,maxAge:900}},nonce:{name:`${t}authjs.nonce`,options:{httpOnly:!0,sameSite:"lax",path:"/",secure:e}},webauthnChallenge:{name:`${t}authjs.challenge`,options:{httpOnly:!0,sameSite:"lax",path:"/",secure:e,maxAge:900}}}}class h{constructor(e,t,r){if(i.add(this),n.set(this,{}),a.set(this,void 0),o.set(this,void 0),u(this,o,r,"f"),u(this,a,e,"f"),!t)return;let{name:s}=e;for(let[e,r]of Object.entries(t))e.startsWith(s)&&r&&(d(this,n,"f")[e]=r)}get value(){return Object.keys(d(this,n,"f")).sort((e,t)=>parseInt(e.split(".").pop()||"0")-parseInt(t.split(".").pop()||"0")).map(e=>d(this,n,"f")[e]).join("")}chunk(e,t){let r=d(this,i,"m",c).call(this);for(let n of d(this,i,"m",s).call(this,{name:d(this,a,"f").name,value:e,options:{...d(this,a,"f").options,...t}}))r[n.name]=n;return Object.values(r)}clean(){return Object.values(d(this,i,"m",c).call(this))}}n=new WeakMap,a=new WeakMap,o=new WeakMap,i=new WeakSet,s=function(e){let t=Math.ceil(e.value.length/3936);if(1===t)return d(this,n,"f")[e.name]=e.value,[e];let r=[];for(let i=0;i<t;i++){let t=`${e.name}.${i}`,a=e.value.substr(3936*i,3936);r.push({...e,name:t,value:a}),d(this,n,"f")[t]=a}return d(this,o,"f").debug("CHUNKING_SESSION_COOKIE",{message:"Session cookie exceeds allowed 4096 bytes.",emptyCookieSize:160,valueSize:e.value.length,chunks:r.map(e=>e.value.length+160)}),r},c=function(){let e={};for(let t in d(this,n,"f"))delete d(this,n,"f")?.[t],e[t]={name:t,value:"",options:{...d(this,a,"f").options,maxAge:0}};return e};class f extends Error{constructor(e,t){e instanceof Error?super(void 0,{cause:{err:e,...e.cause,...t}}):"string"==typeof e?(t instanceof Error&&(t={err:t,...t.cause}),super(e,t)):super(void 0,e),this.name=this.constructor.name,this.type=this.constructor.type??"AuthError",this.kind=this.constructor.kind??"error",Error.captureStackTrace?.(this,this.constructor);let r=`https://errors.authjs.dev#${this.type.toLowerCase()}`;this.message+=`${this.message?". ":""}Read more at ${r}`}}class m extends f{}m.kind="signIn";class g extends f{}g.type="AdapterError";class w extends f{}w.type="AccessDenied";class y extends f{}y.type="CallbackRouteError";class b extends f{}b.type="ErrorPageLoop";class v extends f{}v.type="EventError";class k extends f{}k.type="InvalidCallbackUrl";class x extends m{constructor(){super(...arguments),this.code="credentials"}}x.type="CredentialsSignin";class U extends f{}U.type="InvalidEndpoints";class $ extends f{}$.type="InvalidCheck";class T extends f{}T.type="JWTSessionError";class S extends f{}S.type="MissingAdapter";class A extends f{}A.type="MissingAdapterMethods";class _ extends f{}_.type="MissingAuthorize";class I extends f{}I.type="MissingSecret";class R extends m{}R.type="OAuthAccountNotLinked";class C extends m{}C.type="OAuthCallbackError";class E extends f{}E.type="OAuthProfileParseError";class P extends f{}P.type="SessionTokenError";class O extends m{}O.type="OAuthSignInError";class j extends m{}j.type="EmailSignInError";class L extends f{}L.type="SignOutError";class N extends f{}N.type="UnknownAction";class D extends f{}D.type="UnsupportedStrategy";class q extends f{}q.type="InvalidProvider";class B extends f{}B.type="UntrustedHost";class Z extends f{}Z.type="Verification";class z extends m{}z.type="MissingCSRF";let H=new Set(["CredentialsSignin","OAuthAccountNotLinked","OAuthCallbackError","AccessDenied","Verification","MissingCSRF","AccountNotLinked","WebAuthnVerificationError"]);class W extends f{}W.type="DuplicateConditionalUI";class V extends f{}V.type="MissingWebAuthnAutocomplete";class M extends f{}M.type="WebAuthnVerificationError";class F extends m{}F.type="AccountNotLinked";class X extends f{}X.type="ExperimentalFeatureNotEnabled";let K=!1;function J(e,t){try{return/^https?:/.test(new URL(e,e.startsWith("/")?t:void 0).protocol)}catch{return!1}}let G=!1,Y=!1,Q=!1,ee=["createVerificationToken","useVerificationToken","getUserByEmail"],et=["createUser","getUser","getUserByEmail","getUserByAccount","updateUser","linkAccount","createSession","getSessionAndUser","updateSession","deleteSession"],er=["createUser","getUser","linkAccount","getAccount","getAuthenticator","createAuthenticator","listAuthenticatorsByUserId","updateAuthenticatorCounter"];var ei=r(4169),en=r(21524),ea=r(12472),eo=r(78940),es=r(1683);let ec=/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/,el=/^("?)[\u0021\u0023-\u002B\u002D-\u003A\u003C-\u005B\u005D-\u007E]*\1$/,eu=/^([.]?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)([.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i,ed=/^[\u0020-\u003A\u003D-\u007E]*$/,ep=Object.prototype.toString,eh=(()=>{let e=function(){};return e.prototype=Object.create(null),e})();function ef(e,t){let r=new eh,i=e.length;if(i<2)return r;let n=t?.decode||ey,a=0;do{let t=e.indexOf("=",a);if(-1===t)break;let o=e.indexOf(";",a),s=-1===o?i:o;if(t>s){a=e.lastIndexOf(";",t-1)+1;continue}let c=em(e,a,t),l=eg(e,t,c),u=e.slice(c,l);if(void 0===r[u]){let i=em(e,t+1,s),a=eg(e,s,i),o=n(e.slice(i,a));r[u]=o}a=s+1}while(a<i);return r}function em(e,t,r){do{let r=e.charCodeAt(t);if(32!==r&&9!==r)return t}while(++t<r);return r}function eg(e,t,r){for(;t>r;){let r=e.charCodeAt(--t);if(32!==r&&9!==r)return t+1}return r}function ew(e,t,r){let i=r?.encode||encodeURIComponent;if(!ec.test(e))throw TypeError(`argument name is invalid: ${e}`);let n=i(t);if(!el.test(n))throw TypeError(`argument val is invalid: ${t}`);let a=e+"="+n;if(!r)return a;if(void 0!==r.maxAge){if(!Number.isInteger(r.maxAge))throw TypeError(`option maxAge is invalid: ${r.maxAge}`);a+="; Max-Age="+r.maxAge}if(r.domain){if(!eu.test(r.domain))throw TypeError(`option domain is invalid: ${r.domain}`);a+="; Domain="+r.domain}if(r.path){if(!ed.test(r.path))throw TypeError(`option path is invalid: ${r.path}`);a+="; Path="+r.path}if(r.expires){var o;if(o=r.expires,"[object Date]"!==ep.call(o)||!Number.isFinite(r.expires.valueOf()))throw TypeError(`option expires is invalid: ${r.expires}`);a+="; Expires="+r.expires.toUTCString()}if(r.httpOnly&&(a+="; HttpOnly"),r.secure&&(a+="; Secure"),r.partitioned&&(a+="; Partitioned"),r.priority)switch("string"==typeof r.priority?r.priority.toLowerCase():void 0){case"low":a+="; Priority=Low";break;case"medium":a+="; Priority=Medium";break;case"high":a+="; Priority=High";break;default:throw TypeError(`option priority is invalid: ${r.priority}`)}if(r.sameSite)switch("string"==typeof r.sameSite?r.sameSite.toLowerCase():r.sameSite){case!0:case"strict":a+="; SameSite=Strict";break;case"lax":a+="; SameSite=Lax";break;case"none":a+="; SameSite=None";break;default:throw TypeError(`option sameSite is invalid: ${r.sameSite}`)}return a}function ey(e){if(-1===e.indexOf("%"))return e;try{return decodeURIComponent(e)}catch(t){return e}}let{parse:eb}=l,ev=()=>Date.now()/1e3|0,ek="A256CBC-HS512";async function ex(e){let{token:t={},secret:r,maxAge:i=2592e3,salt:n}=e,a=Array.isArray(r)?r:[r],o=await e$(ek,a[0],n),s=await (0,en.j)({kty:"oct",k:ea.c(o)},`sha${o.byteLength<<3}`);return await new eo.R(t).setProtectedHeader({alg:"dir",enc:ek,kid:s}).setIssuedAt().setExpirationTime(ev()+i).setJti(crypto.randomUUID()).encrypt(o)}async function eU(e){let{token:t,secret:r,salt:i}=e,n=Array.isArray(r)?r:[r];if(!t)return null;let{payload:a}=await (0,es.V)(t,async({kid:e,enc:t})=>{for(let r of n){let n=await e$(t,r,i);if(void 0===e||e===await (0,en.j)({kty:"oct",k:ea.c(n)},`sha${n.byteLength<<3}`))return n}throw Error("no matching decryption secret")},{clockTolerance:15,keyManagementAlgorithms:["dir"],contentEncryptionAlgorithms:[ek,"A256GCM"]});return a}async function e$(e,t,r){let i;switch(e){case"A256CBC-HS512":i=64;break;case"A256GCM":i=32;break;default:throw Error("Unsupported JWT Content Encryption Algorithm")}return await (0,ei.D)("sha256",t,r,`Auth.js Generated Encryption Key (${r})`,i)}async function eT({options:e,paramValue:t,cookieValue:r}){let{url:i,callbacks:n}=e,a=i.origin;return t?a=await n.redirect({url:t,baseUrl:i.origin}):r&&(a=await n.redirect({url:r,baseUrl:i.origin})),{callbackUrl:a,callbackUrlCookie:a!==r?a:void 0}}let eS="\x1b[31m",eA="\x1b[0m",e_={error(e){let t=e instanceof f?e.type:e.name;if(console.error(`${eS}[auth][error]${eA} ${t}: ${e.message}`),e.cause&&"object"==typeof e.cause&&"err"in e.cause&&e.cause.err instanceof Error){let{err:t,...r}=e.cause;console.error(`${eS}[auth][cause]${eA}:`,t.stack),r&&console.error(`${eS}[auth][details]${eA}:`,JSON.stringify(r,null,2))}else e.stack&&console.error(e.stack.replace(/.*/,"").substring(1))},warn(e){let t=`https://warnings.authjs.dev#${e}`;console.warn(`\x1b[33m[auth][warn][${e}]${eA}`,`Read more: ${t}`)},debug(e,t){console.log(`\x1b[90m[auth][debug]:${eA} ${e}`,JSON.stringify(t,null,2))}};function eI(e){let t={...e_};return e.debug||(t.debug=()=>{}),e.logger?.error&&(t.error=e.logger.error),e.logger?.warn&&(t.warn=e.logger.warn),e.logger?.debug&&(t.debug=e.logger.debug),e.logger??(e.logger=t),t}let eR=["providers","session","csrf","signin","signout","callback","verify-request","error","webauthn-options"],{parse:eC,serialize:eE}=l;async function eP(e){if(!("body"in e)||!e.body||"POST"!==e.method)return;let t=e.headers.get("content-type");return t?.includes("application/json")?await e.json():t?.includes("application/x-www-form-urlencoded")?Object.fromEntries(new URLSearchParams(await e.text())):void 0}async function eO(e,t){try{if("GET"!==e.method&&"POST"!==e.method)throw new N("Only GET and POST requests are supported");t.basePath??(t.basePath="/auth");let r=new URL(e.url),{action:i,providerId:n}=function(e,t){let r=e.match(RegExp(`^${t}(.+)`));if(null===r)throw new N(`Cannot parse action at ${e}`);let i=r.at(-1).replace(/^\//,"").split("/").filter(Boolean);if(1!==i.length&&2!==i.length)throw new N(`Cannot parse action at ${e}`);let[n,a]=i;if(!eR.includes(n)||a&&!["signin","callback","webauthn-options"].includes(n))throw new N(`Cannot parse action at ${e}`);return{action:n,providerId:a}}(r.pathname,t.basePath);return{url:r,action:i,providerId:n,method:e.method,headers:Object.fromEntries(e.headers),body:e.body?await eP(e):void 0,cookies:eC(e.headers.get("cookie")??"")??{},error:r.searchParams.get("error")??void 0,query:Object.fromEntries(r.searchParams)}}catch(i){let r=eI(t);r.error(i),r.debug("request",e)}}function ej(e){let t=new Headers(e.headers);e.cookies?.forEach(e=>{let{name:r,value:i,options:n}=e,a=eE(r,i,n);t.has("Set-Cookie")?t.append("Set-Cookie",a):t.set("Set-Cookie",a)});let r=e.body;"application/json"===t.get("content-type")?r=JSON.stringify(e.body):"application/x-www-form-urlencoded"===t.get("content-type")&&(r=new URLSearchParams(e.body).toString());let i=new Response(r,{headers:t,status:e.redirect?302:e.status??200});return e.redirect&&i.headers.set("Location",e.redirect),i}async function eL(e){let t=new TextEncoder().encode(e);return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",t))).map(e=>e.toString(16).padStart(2,"0")).join("").toString()}function eN(e){let t=e=>("0"+e.toString(16)).slice(-2);return Array.from(crypto.getRandomValues(new Uint8Array(e))).reduce((e,r)=>e+t(r),"")}async function eD({options:e,cookieValue:t,isPost:r,bodyValue:i}){if(t){let[n,a]=t.split("|");if(a===await eL(`${n}${e.secret}`))return{csrfTokenVerified:r&&n===i,csrfToken:n}}let n=eN(32),a=await eL(`${n}${e.secret}`);return{cookie:`${n}|${a}`,csrfToken:n}}function eq(e,t){if(!t)throw new z(`CSRF token was missing during an action ${e}`)}function eB(e){return null!==e&&"object"==typeof e}function eZ(e,...t){if(!t.length)return e;let r=t.shift();if(eB(e)&&eB(r))for(let t in r)eB(r[t])?(eB(e[t])||(e[t]=Array.isArray(r[t])?[]:{}),eZ(e[t],r[t])):void 0!==r[t]&&(e[t]=r[t]);return eZ(e,...t)}let ez=Symbol("skip-csrf-check"),eH=Symbol("return-type-raw"),eW=Symbol("custom-fetch"),eV=Symbol("conform-internal"),eM=e=>eX({id:e.sub??e.id??crypto.randomUUID(),name:e.name??e.nickname??e.preferred_username,email:e.email,image:e.picture}),eF=e=>eX({access_token:e.access_token,id_token:e.id_token,refresh_token:e.refresh_token,expires_at:e.expires_at,scope:e.scope,token_type:e.token_type,session_state:e.session_state});function eX(e){let t={};for(let[r,i]of Object.entries(e))void 0!==i&&(t[r]=i);return t}function eK(e,t){if(!e&&t)return;if("string"==typeof e)return{url:new URL(e)};let r=new URL(e?.url??"https://authjs.dev");if(e?.params!=null)for(let[t,i]of Object.entries(e.params))"claims"===t&&(i=JSON.stringify(i)),r.searchParams.set(t,String(i));return{url:r,request:e?.request,conform:e?.conform,...e?.clientPrivateKey?{clientPrivateKey:e?.clientPrivateKey}:null}}let eJ={signIn:()=>!0,redirect:({url:e,baseUrl:t})=>e.startsWith("/")?`${t}${e}`:new URL(e).origin===t?e:t,session:({session:e})=>({user:{name:e.user?.name,email:e.user?.email,image:e.user?.image},expires:e.expires?.toISOString?.()??e.expires}),jwt:({token:e})=>e};async function eG({authOptions:e,providerId:t,action:r,url:i,cookies:n,callbackUrl:a,csrfToken:o,csrfDisabled:s,isPost:c}){var l;let u=eI(e),{providers:d,provider:h}=function(e){let{providerId:t,config:r}=e,i=new URL(r.basePath??"/auth",e.url.origin),n=r.providers.map(e=>{let t="function"==typeof e?e():e,{options:n,...a}=t,o=n?.id??a.id,s=eZ(a,n,{signinUrl:`${i}/signin/${o}`,callbackUrl:`${i}/callback/${o}`});if("oauth"===t.type||"oidc"===t.type){s.redirectProxyUrl??(s.redirectProxyUrl=n?.redirectProxyUrl??r.redirectProxyUrl);let e=function(e){e.issuer&&(e.wellKnown??(e.wellKnown=`${e.issuer}/.well-known/openid-configuration`));let t=eK(e.authorization,e.issuer);t&&!t.url?.searchParams.has("scope")&&t.url.searchParams.set("scope","openid profile email");let r=eK(e.token,e.issuer),i=eK(e.userinfo,e.issuer),n=e.checks??["pkce"];return e.redirectProxyUrl&&(n.includes("state")||n.push("state"),e.redirectProxyUrl=`${e.redirectProxyUrl}/callback/${e.id}`),{...e,authorization:t,token:r,checks:n,userinfo:i,profile:e.profile??eM,account:e.account??eF}}(s);return e.authorization?.url.searchParams.get("response_mode")==="form_post"&&delete e.redirectProxyUrl,e[eW]??(e[eW]=n?.[eW]),e}return s}),a=n.find(({id:e})=>e===t);if(t&&!a){let e=n.map(e=>e.id).join(", ");throw Error(`Provider with id "${t}" not found. Available providers: [${e}].`)}return{providers:n,provider:a}}({url:i,providerId:t,config:e}),f=!1;if((h?.type==="oauth"||h?.type==="oidc")&&h.redirectProxyUrl)try{f=new URL(h.redirectProxyUrl).origin===i.origin}catch{throw TypeError(`redirectProxyUrl must be a valid URL. Received: ${h.redirectProxyUrl}`)}let m={debug:!1,pages:{},theme:{colorScheme:"auto",logo:"",brandColor:"",buttonText:""},...e,url:i,action:r,provider:h,cookies:eZ(p(e.useSecureCookies??"https:"===i.protocol),e.cookies),providers:d,session:{strategy:e.adapter?"database":"jwt",maxAge:2592e3,updateAge:86400,generateSessionToken:()=>crypto.randomUUID(),...e.session},jwt:{secret:e.secret,maxAge:e.session?.maxAge??2592e3,encode:ex,decode:eU,...e.jwt},events:Object.keys(l=e.events??{}).reduce((e,t)=>(e[t]=async(...e)=>{try{let r=l[t];return await r(...e)}catch(e){u.error(new v(e))}},e),{}),adapter:function(e,t){if(e)return Object.keys(e).reduce((r,i)=>(r[i]=async(...r)=>{try{t.debug(`adapter_${i}`,{args:r});let n=e[i];return await n(...r)}catch(r){let e=new g(r);throw t.error(e),e}},r),{})}(e.adapter,u),callbacks:{...eJ,...e.callbacks},logger:u,callbackUrl:i.origin,isOnRedirectProxy:f,experimental:{...e.experimental}},w=[];if(s)m.csrfTokenVerified=!0;else{let{csrfToken:e,cookie:t,csrfTokenVerified:r}=await eD({options:m,cookieValue:n?.[m.cookies.csrfToken.name],isPost:c,bodyValue:o});m.csrfToken=e,m.csrfTokenVerified=r,t&&w.push({name:m.cookies.csrfToken.name,value:t,options:m.cookies.csrfToken.options})}let{callbackUrl:y,callbackUrlCookie:b}=await eT({options:m,cookieValue:n?.[m.cookies.callbackUrl.name],paramValue:a});return m.callbackUrl=y,b&&w.push({name:m.cookies.callbackUrl.name,value:b,options:m.cookies.callbackUrl.options}),{options:m,cookies:w}}var eY=r(60614),eQ=r(44600);async function e0(e,t){let r=window.SimpleWebAuthnBrowser;async function i(r){let i=new URL(`${e}/webauthn-options/${t}`);r&&i.searchParams.append("action",r),a().forEach(e=>{i.searchParams.append(e.name,e.value)});let n=await fetch(i);if(!n.ok){console.error("Failed to fetch options",n);return}return n.json()}function n(){let e=`#${t}-form`,r=document.querySelector(e);if(!r)throw Error(`Form '${e}' not found`);return r}function a(){return Array.from(n().querySelectorAll("input[data-form-field]"))}async function o(e,t){let r=n();if(e){let t=document.createElement("input");t.type="hidden",t.name="action",t.value=e,r.appendChild(t)}if(t){let e=document.createElement("input");e.type="hidden",e.name="data",e.value=JSON.stringify(t),r.appendChild(e)}return r.submit()}async function s(e,t){let i=await r.startAuthentication(e,t);return await o("authenticate",i)}async function c(e){a().forEach(e=>{if(e.required&&!e.value)throw Error(`Missing required field: ${e.name}`)});let t=await r.startRegistration(e);return await o("register",t)}async function l(){if(!r.browserSupportsWebAuthnAutofill())return;let e=await i("authenticate");if(!e){console.error("Failed to fetch option for autofill authentication");return}try{await s(e.options,!0)}catch(e){console.error(e)}}(async function(){let e=n();if(!r.browserSupportsWebAuthn()){e.style.display="none";return}e&&e.addEventListener("submit",async e=>{e.preventDefault();let t=await i(void 0);if(!t){console.error("Failed to fetch options for form submission");return}if("authenticate"===t.action)try{await s(t.options,!1)}catch(e){console.error(e)}else if("register"===t.action)try{await c(t.options)}catch(e){console.error(e)}})})(),l()}let e1={default:"Unable to sign in.",Signin:"Try signing in with a different account.",OAuthSignin:"Try signing in with a different account.",OAuthCallbackError:"Try signing in with a different account.",OAuthCreateAccount:"Try signing in with a different account.",EmailCreateAccount:"Try signing in with a different account.",Callback:"Try signing in with a different account.",OAuthAccountNotLinked:"To confirm your identity, sign in with the same account you used originally.",EmailSignin:"The e-mail could not be sent.",CredentialsSignin:"Sign in failed. Check the details you provided are correct.",SessionRequired:"Please sign in to access this page."},e2=`:root {
  --border-width: 1px;
  --border-radius: 0.5rem;
  --color-error: #c94b4b;
  --color-info: #157efb;
  --color-info-hover: #0f6ddb;
  --color-info-text: #fff;
}

.__next-auth-theme-auto,
.__next-auth-theme-light {
  --color-background: #ececec;
  --color-background-hover: rgba(236, 236, 236, 0.8);
  --color-background-card: #fff;
  --color-text: #000;
  --color-primary: #444;
  --color-control-border: #bbb;
  --color-button-active-background: #f9f9f9;
  --color-button-active-border: #aaa;
  --color-separator: #ccc;
  --provider-bg: #fff;
  --provider-bg-hover: color-mix(
    in srgb,
    var(--provider-brand-color) 30%,
    #fff
  );
}

.__next-auth-theme-dark {
  --color-background: #161b22;
  --color-background-hover: rgba(22, 27, 34, 0.8);
  --color-background-card: #0d1117;
  --color-text: #fff;
  --color-primary: #ccc;
  --color-control-border: #555;
  --color-button-active-background: #060606;
  --color-button-active-border: #666;
  --color-separator: #444;
  --provider-bg: #161b22;
  --provider-bg-hover: color-mix(
    in srgb,
    var(--provider-brand-color) 30%,
    #000
  );
}

.__next-auth-theme-dark img[src$="42-school.svg"],
  .__next-auth-theme-dark img[src$="apple.svg"],
  .__next-auth-theme-dark img[src$="boxyhq-saml.svg"],
  .__next-auth-theme-dark img[src$="eveonline.svg"],
  .__next-auth-theme-dark img[src$="github.svg"],
  .__next-auth-theme-dark img[src$="mailchimp.svg"],
  .__next-auth-theme-dark img[src$="medium.svg"],
  .__next-auth-theme-dark img[src$="okta.svg"],
  .__next-auth-theme-dark img[src$="patreon.svg"],
  .__next-auth-theme-dark img[src$="ping-id.svg"],
  .__next-auth-theme-dark img[src$="roblox.svg"],
  .__next-auth-theme-dark img[src$="threads.svg"],
  .__next-auth-theme-dark img[src$="wikimedia.svg"] {
    filter: invert(1);
  }

.__next-auth-theme-dark #submitButton {
    background-color: var(--provider-bg, var(--color-info));
  }

@media (prefers-color-scheme: dark) {
  .__next-auth-theme-auto {
    --color-background: #161b22;
    --color-background-hover: rgba(22, 27, 34, 0.8);
    --color-background-card: #0d1117;
    --color-text: #fff;
    --color-primary: #ccc;
    --color-control-border: #555;
    --color-button-active-background: #060606;
    --color-button-active-border: #666;
    --color-separator: #444;
    --provider-bg: #161b22;
    --provider-bg-hover: color-mix(
      in srgb,
      var(--provider-brand-color) 30%,
      #000
    );
  }
    .__next-auth-theme-auto img[src$="42-school.svg"],
    .__next-auth-theme-auto img[src$="apple.svg"],
    .__next-auth-theme-auto img[src$="boxyhq-saml.svg"],
    .__next-auth-theme-auto img[src$="eveonline.svg"],
    .__next-auth-theme-auto img[src$="github.svg"],
    .__next-auth-theme-auto img[src$="mailchimp.svg"],
    .__next-auth-theme-auto img[src$="medium.svg"],
    .__next-auth-theme-auto img[src$="okta.svg"],
    .__next-auth-theme-auto img[src$="patreon.svg"],
    .__next-auth-theme-auto img[src$="ping-id.svg"],
    .__next-auth-theme-auto img[src$="roblox.svg"],
    .__next-auth-theme-auto img[src$="threads.svg"],
    .__next-auth-theme-auto img[src$="wikimedia.svg"] {
      filter: invert(1);
    }
    .__next-auth-theme-auto #submitButton {
      background-color: var(--provider-bg, var(--color-info));
    }
}

html {
  box-sizing: border-box;
}

*,
*:before,
*:after {
  box-sizing: inherit;
  margin: 0;
  padding: 0;
}

body {
  background-color: var(--color-background);
  margin: 0;
  padding: 0;
  font-family:
    ui-sans-serif,
    system-ui,
    -apple-system,
    BlinkMacSystemFont,
    "Segoe UI",
    Roboto,
    "Helvetica Neue",
    Arial,
    "Noto Sans",
    sans-serif,
    "Apple Color Emoji",
    "Segoe UI Emoji",
    "Segoe UI Symbol",
    "Noto Color Emoji";
}

h1 {
  margin-bottom: 1.5rem;
  padding: 0 1rem;
  font-weight: 400;
  color: var(--color-text);
}

p {
  margin-bottom: 1.5rem;
  padding: 0 1rem;
  color: var(--color-text);
}

form {
  margin: 0;
  padding: 0;
}

label {
  font-weight: 500;
  text-align: left;
  margin-bottom: 0.25rem;
  display: block;
  color: var(--color-text);
}

input[type] {
  box-sizing: border-box;
  display: block;
  width: 100%;
  padding: 0.5rem 1rem;
  border: var(--border-width) solid var(--color-control-border);
  background: var(--color-background-card);
  font-size: 1rem;
  border-radius: var(--border-radius);
  color: var(--color-text);
}

p {
  font-size: 1.1rem;
  line-height: 2rem;
}

a.button {
  text-decoration: none;
  line-height: 1rem;
}

a.button:link,
  a.button:visited {
    background-color: var(--color-background);
    color: var(--color-primary);
  }

button,
a.button {
  padding: 0.75rem 1rem;
  color: var(--provider-color, var(--color-primary));
  background-color: var(--provider-bg, var(--color-background));
  border: 1px solid #00000031;
  font-size: 0.9rem;
  height: 50px;
  border-radius: var(--border-radius);
  transition: background-color 250ms ease-in-out;
  font-weight: 300;
  position: relative;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

:is(button,a.button):hover {
    background-color: var(--provider-bg-hover, var(--color-background-hover));
    cursor: pointer;
  }

:is(button,a.button):active {
    cursor: pointer;
  }

:is(button,a.button) span {
    color: var(--provider-bg);
  }

#submitButton {
  color: var(--button-text-color, var(--color-info-text));
  background-color: var(--brand-color, var(--color-info));
  width: 100%;
}

#submitButton:hover {
    background-color: var(
      --button-hover-bg,
      var(--color-info-hover)
    ) !important;
  }

a.site {
  color: var(--color-primary);
  text-decoration: none;
  font-size: 1rem;
  line-height: 2rem;
}

a.site:hover {
    text-decoration: underline;
  }

.page {
  position: absolute;
  width: 100%;
  height: 100%;
  display: grid;
  place-items: center;
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

.page > div {
    text-align: center;
  }

.error a.button {
    padding-left: 2rem;
    padding-right: 2rem;
    margin-top: 0.5rem;
  }

.error .message {
    margin-bottom: 1.5rem;
  }

.signin input[type="text"] {
    margin-left: auto;
    margin-right: auto;
    display: block;
  }

.signin hr {
    display: block;
    border: 0;
    border-top: 1px solid var(--color-separator);
    margin: 2rem auto 1rem auto;
    overflow: visible;
  }

.signin hr::before {
      content: "or";
      background: var(--color-background-card);
      color: #888;
      padding: 0 0.4rem;
      position: relative;
      top: -0.7rem;
    }

.signin .error {
    background: #f5f5f5;
    font-weight: 500;
    border-radius: 0.3rem;
    background: var(--color-error);
  }

.signin .error p {
      text-align: left;
      padding: 0.5rem 1rem;
      font-size: 0.9rem;
      line-height: 1.2rem;
      color: var(--color-info-text);
    }

.signin > div,
  .signin form {
    display: block;
  }

.signin > div input[type], .signin form input[type] {
      margin-bottom: 0.5rem;
    }

.signin > div button, .signin form button {
      width: 100%;
    }

.signin .provider + .provider {
    margin-top: 1rem;
  }

.logo {
  display: inline-block;
  max-width: 150px;
  margin: 1.25rem 0;
  max-height: 70px;
}

.card {
  background-color: var(--color-background-card);
  border-radius: 1rem;
  padding: 1.25rem 2rem;
}

.card .header {
    color: var(--color-primary);
  }

.card input[type]::-moz-placeholder {
    color: color-mix(
      in srgb,
      var(--color-text) 20%,
      var(--color-button-active-background)
    );
  }

.card input[type]::placeholder {
    color: color-mix(
      in srgb,
      var(--color-text) 20%,
      var(--color-button-active-background)
    );
  }

.card input[type] {
    background: color-mix(in srgb, var(--color-background-card) 95%, black);
  }

.section-header {
  color: var(--color-text);
}

@media screen and (min-width: 450px) {
  .card {
    margin: 2rem 0;
    width: 368px;
  }
}

@media screen and (max-width: 450px) {
  .card {
    margin: 1rem 0;
    width: 343px;
  }
}
`;function e5({html:e,title:t,status:r,cookies:i,theme:n,headTags:a}){return{cookies:i,status:r,headers:{"Content-Type":"text/html"},body:`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width, initial-scale=1.0"><style>${e2}</style><title>${t}</title>${a??""}</head><body class="__next-auth-theme-${n?.colorScheme??"auto"}"><div class="page">${(0,eY.Dq)(e)}</div></body></html>`}}function e3(e){let{url:t,theme:r,query:i,cookies:n,pages:a,providers:o}=e;return{csrf:(e,t,r)=>e?(t.logger.warn("csrf-disabled"),r.push({name:t.cookies.csrfToken.name,value:"",options:{...t.cookies.csrfToken.options,maxAge:0}}),{status:404,cookies:r}):{headers:{"Content-Type":"application/json"},body:{csrfToken:t.csrfToken},cookies:r},providers:e=>({headers:{"Content-Type":"application/json"},body:e.reduce((e,{id:t,name:r,type:i,signinUrl:n,callbackUrl:a})=>(e[t]={id:t,name:r,type:i,signinUrl:n,callbackUrl:a},e),{})}),signin(t,s){if(t)throw new N("Unsupported action");if(a?.signIn){let t=`${a.signIn}${a.signIn.includes("?")?"&":"?"}${new URLSearchParams({callbackUrl:e.callbackUrl??"/"})}`;return s&&(t=`${t}&${new URLSearchParams({error:s})}`),{redirect:t,cookies:n}}let c=o?.find(e=>"webauthn"===e.type&&e.enableConditionalUI&&!!e.simpleWebAuthnBrowserVersion),l="";if(c){let{simpleWebAuthnBrowserVersion:e}=c;l=`<script src="https://unpkg.com/@simplewebauthn/browser@${e}/dist/bundle/index.umd.min.js" crossorigin="anonymous"></script>`}return e5({cookies:n,theme:r,html:function(e){let{csrfToken:t,providers:r=[],callbackUrl:i,theme:n,email:a,error:o}=e;"undefined"!=typeof document&&n?.brandColor&&document.documentElement.style.setProperty("--brand-color",n.brandColor),"undefined"!=typeof document&&n?.buttonText&&document.documentElement.style.setProperty("--button-text-color",n.buttonText);let s=o&&(e1[o]??e1.default),c=r.find(e=>"webauthn"===e.type&&e.enableConditionalUI)?.id;return(0,eQ.BX)("div",{className:"signin",children:[n?.brandColor&&(0,eQ.tZ)("style",{dangerouslySetInnerHTML:{__html:`:root {--brand-color: ${n.brandColor}}`}}),n?.buttonText&&(0,eQ.tZ)("style",{dangerouslySetInnerHTML:{__html:`
        :root {
          --button-text-color: ${n.buttonText}
        }
      `}}),(0,eQ.BX)("div",{className:"card",children:[s&&(0,eQ.tZ)("div",{className:"error",children:(0,eQ.tZ)("p",{children:s})}),n?.logo&&(0,eQ.tZ)("img",{src:n.logo,alt:"Logo",className:"logo"}),r.map((e,n)=>{let o,s,c;("oauth"===e.type||"oidc"===e.type)&&({bg:o="#fff",brandColor:s,logo:c=`https://authjs.dev/img/providers/${e.id}.svg`}=e.style??{});let l=s??o??"#fff";return(0,eQ.BX)("div",{className:"provider",children:["oauth"===e.type||"oidc"===e.type?(0,eQ.BX)("form",{action:e.signinUrl,method:"POST",children:[(0,eQ.tZ)("input",{type:"hidden",name:"csrfToken",value:t}),i&&(0,eQ.tZ)("input",{type:"hidden",name:"callbackUrl",value:i}),(0,eQ.BX)("button",{type:"submit",className:"button",style:{"--provider-brand-color":l},tabIndex:0,children:[(0,eQ.BX)("span",{style:{filter:"invert(1) grayscale(1) brightness(1.3) contrast(9000)","mix-blend-mode":"luminosity",opacity:.95},children:["Sign in with ",e.name]}),c&&(0,eQ.tZ)("img",{loading:"lazy",height:24,src:c})]})]}):null,("email"===e.type||"credentials"===e.type||"webauthn"===e.type)&&n>0&&"email"!==r[n-1].type&&"credentials"!==r[n-1].type&&"webauthn"!==r[n-1].type&&(0,eQ.tZ)("hr",{}),"email"===e.type&&(0,eQ.BX)("form",{action:e.signinUrl,method:"POST",children:[(0,eQ.tZ)("input",{type:"hidden",name:"csrfToken",value:t}),(0,eQ.tZ)("label",{className:"section-header",htmlFor:`input-email-for-${e.id}-provider`,children:"Email"}),(0,eQ.tZ)("input",{id:`input-email-for-${e.id}-provider`,autoFocus:!0,type:"email",name:"email",value:a,placeholder:"email@example.com",required:!0}),(0,eQ.BX)("button",{id:"submitButton",type:"submit",tabIndex:0,children:["Sign in with ",e.name]})]}),"credentials"===e.type&&(0,eQ.BX)("form",{action:e.callbackUrl,method:"POST",children:[(0,eQ.tZ)("input",{type:"hidden",name:"csrfToken",value:t}),Object.keys(e.credentials).map(t=>(0,eQ.BX)("div",{children:[(0,eQ.tZ)("label",{className:"section-header",htmlFor:`input-${t}-for-${e.id}-provider`,children:e.credentials[t].label??t}),(0,eQ.tZ)("input",{name:t,id:`input-${t}-for-${e.id}-provider`,type:e.credentials[t].type??"text",placeholder:e.credentials[t].placeholder??"",...e.credentials[t]})]},`input-group-${e.id}`)),(0,eQ.BX)("button",{id:"submitButton",type:"submit",tabIndex:0,children:["Sign in with ",e.name]})]}),"webauthn"===e.type&&(0,eQ.BX)("form",{action:e.callbackUrl,method:"POST",id:`${e.id}-form`,children:[(0,eQ.tZ)("input",{type:"hidden",name:"csrfToken",value:t}),Object.keys(e.formFields).map(t=>(0,eQ.BX)("div",{children:[(0,eQ.tZ)("label",{className:"section-header",htmlFor:`input-${t}-for-${e.id}-provider`,children:e.formFields[t].label??t}),(0,eQ.tZ)("input",{name:t,"data-form-field":!0,id:`input-${t}-for-${e.id}-provider`,type:e.formFields[t].type??"text",placeholder:e.formFields[t].placeholder??"",...e.formFields[t]})]},`input-group-${e.id}`)),(0,eQ.BX)("button",{id:`submitButton-${e.id}`,type:"submit",tabIndex:0,children:["Sign in with ",e.name]})]}),("email"===e.type||"credentials"===e.type||"webauthn"===e.type)&&n+1<r.length&&(0,eQ.tZ)("hr",{})]},e.id)})]}),c&&function(e){let t=`
const currentURL = window.location.href;
const authURL = currentURL.substring(0, currentURL.lastIndexOf('/'));
(${e0})(authURL, "${e}");
`;return(0,eQ.tZ)(eQ.HY,{children:(0,eQ.tZ)("script",{dangerouslySetInnerHTML:{__html:t}})})}(c)]})}({csrfToken:e.csrfToken,providers:e.providers?.filter(e=>["email","oauth","oidc"].includes(e.type)||"credentials"===e.type&&e.credentials||"webauthn"===e.type&&e.formFields||!1),callbackUrl:e.callbackUrl,theme:e.theme,error:s,...i}),title:"Sign In",headTags:l})},signout:()=>a?.signOut?{redirect:a.signOut,cookies:n}:e5({cookies:n,theme:r,html:function(e){let{url:t,csrfToken:r,theme:i}=e;return(0,eQ.BX)("div",{className:"signout",children:[i?.brandColor&&(0,eQ.tZ)("style",{dangerouslySetInnerHTML:{__html:`
        :root {
          --brand-color: ${i.brandColor}
        }
      `}}),i?.buttonText&&(0,eQ.tZ)("style",{dangerouslySetInnerHTML:{__html:`
        :root {
          --button-text-color: ${i.buttonText}
        }
      `}}),(0,eQ.BX)("div",{className:"card",children:[i?.logo&&(0,eQ.tZ)("img",{src:i.logo,alt:"Logo",className:"logo"}),(0,eQ.tZ)("h1",{children:"Signout"}),(0,eQ.tZ)("p",{children:"Are you sure you want to sign out?"}),(0,eQ.BX)("form",{action:t?.toString(),method:"POST",children:[(0,eQ.tZ)("input",{type:"hidden",name:"csrfToken",value:r}),(0,eQ.tZ)("button",{id:"submitButton",type:"submit",children:"Sign out"})]})]})]})}({csrfToken:e.csrfToken,url:t,theme:r}),title:"Sign Out"}),verifyRequest:e=>a?.verifyRequest?{redirect:`${a.verifyRequest}${t?.search??""}`,cookies:n}:e5({cookies:n,theme:r,html:function(e){let{url:t,theme:r}=e;return(0,eQ.BX)("div",{className:"verify-request",children:[r.brandColor&&(0,eQ.tZ)("style",{dangerouslySetInnerHTML:{__html:`
        :root {
          --brand-color: ${r.brandColor}
        }
      `}}),(0,eQ.BX)("div",{className:"card",children:[r.logo&&(0,eQ.tZ)("img",{src:r.logo,alt:"Logo",className:"logo"}),(0,eQ.tZ)("h1",{children:"Check your email"}),(0,eQ.tZ)("p",{children:"A sign in link has been sent to your email address."}),(0,eQ.tZ)("p",{children:(0,eQ.tZ)("a",{className:"site",href:t.origin,children:t.host})})]})]})}({url:t,theme:r,...e}),title:"Verify Request"}),error:e=>a?.error?{redirect:`${a.error}${a.error.includes("?")?"&":"?"}error=${e}`,cookies:n}:e5({cookies:n,theme:r,...function(e){let{url:t,error:r="default",theme:i}=e,n=`${t}/signin`,a={default:{status:200,heading:"Error",message:(0,eQ.tZ)("p",{children:(0,eQ.tZ)("a",{className:"site",href:t?.origin,children:t?.host})})},Configuration:{status:500,heading:"Server error",message:(0,eQ.BX)("div",{children:[(0,eQ.tZ)("p",{children:"There is a problem with the server configuration."}),(0,eQ.tZ)("p",{children:"Check the server logs for more information."})]})},AccessDenied:{status:403,heading:"Access Denied",message:(0,eQ.BX)("div",{children:[(0,eQ.tZ)("p",{children:"You do not have permission to sign in."}),(0,eQ.tZ)("p",{children:(0,eQ.tZ)("a",{className:"button",href:n,children:"Sign in"})})]})},Verification:{status:403,heading:"Unable to sign in",message:(0,eQ.BX)("div",{children:[(0,eQ.tZ)("p",{children:"The sign in link is no longer valid."}),(0,eQ.tZ)("p",{children:"It may have been used already or it may have expired."})]}),signin:(0,eQ.tZ)("a",{className:"button",href:n,children:"Sign in"})}},{status:o,heading:s,message:c,signin:l}=a[r]??a.default;return{status:o,html:(0,eQ.BX)("div",{className:"error",children:[i?.brandColor&&(0,eQ.tZ)("style",{dangerouslySetInnerHTML:{__html:`
        :root {
          --brand-color: ${i?.brandColor}
        }
      `}}),(0,eQ.BX)("div",{className:"card",children:[i?.logo&&(0,eQ.tZ)("img",{src:i?.logo,alt:"Logo",className:"logo"}),(0,eQ.tZ)("h1",{children:s}),(0,eQ.tZ)("div",{className:"message",children:c}),l]})]})}}({url:t,theme:r,error:e}),title:"Error"})}}function e6(e,t=Date.now()){return new Date(t+1e3*e)}async function e4(e,t,r,i){if(!r?.providerAccountId||!r.type)throw Error("Missing or invalid provider account");if(!["email","oauth","oidc","webauthn"].includes(r.type))throw Error("Provider not supported");let{adapter:n,jwt:a,events:o,session:{strategy:s,generateSessionToken:c}}=i;if(!n)return{user:t,account:r};let l=r,{createUser:u,updateUser:d,getUser:p,getUserByAccount:h,getUserByEmail:f,linkAccount:m,createSession:g,getSessionAndUser:w,deleteSession:y}=n,b=null,v=null,k=!1,x="jwt"===s;if(e){if(x)try{let t=i.cookies.sessionToken.name;(b=await a.decode({...a,token:e,salt:t}))&&"sub"in b&&b.sub&&(v=await p(b.sub))}catch{}else{let t=await w(e);t&&(b=t.session,v=t.user)}}if("email"===l.type){let r=await f(t.email);return r?(v?.id!==r.id&&!x&&e&&await y(e),v=await d({id:r.id,emailVerified:new Date}),await o.updateUser?.({user:v})):(v=await u({...t,emailVerified:new Date}),await o.createUser?.({user:v}),k=!0),{session:b=x?{}:await g({sessionToken:c(),userId:v.id,expires:e6(i.session.maxAge)}),user:v,isNewUser:k}}if("webauthn"===l.type){let e=await h({providerAccountId:l.providerAccountId,provider:l.provider});if(e){if(v){if(e.id===v.id){let e={...l,userId:v.id};return{session:b,user:v,isNewUser:k,account:e}}throw new F("The account is already associated with another user",{provider:l.provider})}b=x?{}:await g({sessionToken:c(),userId:e.id,expires:e6(i.session.maxAge)});let t={...l,userId:e.id};return{session:b,user:e,isNewUser:k,account:t}}{if(v){await m({...l,userId:v.id}),await o.linkAccount?.({user:v,account:l,profile:t});let e={...l,userId:v.id};return{session:b,user:v,isNewUser:k,account:e}}if(t.email?await f(t.email):null)throw new F("Another account already exists with the same e-mail address",{provider:l.provider});v=await u({...t}),await o.createUser?.({user:v}),await m({...l,userId:v.id}),await o.linkAccount?.({user:v,account:l,profile:t}),b=x?{}:await g({sessionToken:c(),userId:v.id,expires:e6(i.session.maxAge)});let e={...l,userId:v.id};return{session:b,user:v,isNewUser:!0,account:e}}}let U=await h({providerAccountId:l.providerAccountId,provider:l.provider});if(U){if(v){if(U.id===v.id)return{session:b,user:v,isNewUser:k};throw new R("The account is already associated with another user",{provider:l.provider})}return{session:b=x?{}:await g({sessionToken:c(),userId:U.id,expires:e6(i.session.maxAge)}),user:U,isNewUser:k}}{let{provider:e}=i,{type:r,provider:n,providerAccountId:a,userId:s,...d}=l;if(l=Object.assign(e.account(d)??{},{providerAccountId:a,provider:n,type:r,userId:s}),v)return await m({...l,userId:v.id}),await o.linkAccount?.({user:v,account:l,profile:t}),{session:b,user:v,isNewUser:k};let p=t.email?await f(t.email):null;if(p){let e=i.provider;if(e?.allowDangerousEmailAccountLinking)v=p,k=!1;else throw new R("Another account already exists with the same e-mail address",{provider:l.provider})}else v=await u({...t,emailVerified:null}),k=!0;return await o.createUser?.({user:v}),await m({...l,userId:v.id}),await o.linkAccount?.({user:v,account:l,profile:t}),{session:b=x?{}:await g({sessionToken:c(),userId:v.id,expires:e6(i.session.maxAge)}),user:v,isNewUser:k}}}var e9=r(54440);async function e7(e,t,r){let{cookies:i,logger:n}=r,a=i[e],o=new Date;o.setTime(o.getTime()+9e5),n.debug(`CREATE_${e.toUpperCase()}`,{name:a.name,payload:t,COOKIE_TTL:900,expires:o});let s=await ex({...r.jwt,maxAge:900,token:{value:t},salt:a.name}),c={...a.options,expires:o};return{name:a.name,value:s,options:c}}async function e8(e,t,r){try{let{logger:i,cookies:n,jwt:a}=r;if(i.debug(`PARSE_${e.toUpperCase()}`,{cookie:t}),!t)throw new $(`${e} cookie was missing`);let o=await eU({...a,token:t,salt:n[e].name});if(o?.value)return o.value;throw Error("Invalid cookie")}catch(t){throw new $(`${e} value could not be parsed`,{cause:t})}}function te(e,t,r){let{logger:i,cookies:n}=t,a=n[e];i.debug(`CLEAR_${e.toUpperCase()}`,{cookie:a}),r.push({name:a.name,value:"",options:{...n[e].options,maxAge:0}})}function tt(e,t){return async function(r,i,n){let{provider:a,logger:o}=n;if(!a?.checks?.includes(e))return;let s=r?.[n.cookies[t].name];o.debug(`USE_${t.toUpperCase()}`,{value:s});let c=await e8(t,s,n);return te(t,n,i),c}}let tr={async create(e){let t=e9.g(),r=await e9.Di(t);return{cookie:await e7("pkceCodeVerifier",t,e),value:r}},use:tt("pkce","pkceCodeVerifier")},ti="encodedState",tn={async create(e,t){let{provider:r}=e;if(!r.checks.includes("state")){if(t)throw new $("State data was provided but the provider is not configured to use state");return}let i={origin:t,random:e9.VA()},n=await ex({secret:e.jwt.secret,token:i,salt:ti,maxAge:900});return{cookie:await e7("state",n,e),value:n}},use:tt("state","state"),async decode(e,t){try{t.logger.debug("DECODE_STATE",{state:e});let r=await eU({secret:t.jwt.secret,token:e,salt:ti});if(r)return r;throw Error("Invalid state")}catch(e){throw new $("State could not be decoded",{cause:e})}}},ta={async create(e){if(!e.provider.checks.includes("nonce"))return;let t=e9.wO();return{cookie:await e7("nonce",t,e),value:t}},use:tt("nonce","nonce")},to="encodedWebauthnChallenge",ts={create:async(e,t,r)=>({cookie:await e7("webauthnChallenge",await ex({secret:e.jwt.secret,token:{challenge:t,registerData:r},salt:to,maxAge:900}),e)}),async use(e,t,r){let i=t?.[e.cookies.webauthnChallenge.name],n=await e8("webauthnChallenge",i,e),a=await eU({secret:e.jwt.secret,token:n,salt:to});if(te("webauthnChallenge",e,r),!a)throw new $("WebAuthn challenge was missing");return a}};var tc=r(91453);function tl(e){return encodeURIComponent(e).replace(/%20/g,"+")}async function tu(e,t,r){let i,n,a,o;let{logger:s,provider:c}=r,{token:l,userinfo:u}=c;if(l?.url&&"authjs.dev"!==l.url.host||u?.url&&"authjs.dev"!==u.url.host)i={issuer:c.issuer??"https://authjs.dev",token_endpoint:l?.url.toString(),userinfo_endpoint:u?.url.toString()};else{let e=new URL(c.issuer),t=await e9.FC(e,{[e9.TZ]:!0,[e9.rK]:c[eW]});if(!(i=await e9.hS(e,t)).token_endpoint)throw TypeError("TODO: Authorization server did not provide a token endpoint.");if(!i.userinfo_endpoint)throw TypeError("TODO: Authorization server did not provide a userinfo endpoint.")}let d={client_id:c.clientId,...c.client};switch(d.token_endpoint_auth_method){case void 0:case"client_secret_basic":n=(e,t,r,i)=>{i.set("authorization",function(e,t){let r=tl(e),i=tl(t),n=btoa(`${r}:${i}`);return`Basic ${n}`}(c.clientId,c.clientSecret))};break;case"client_secret_post":n=e9.ON(c.clientSecret);break;case"client_secret_jwt":n=e9.RM(c.clientSecret);break;case"private_key_jwt":n=e9.rH(c.token.clientPrivateKey,{[e9.e7](e,t){t.aud=[i.issuer,i.token_endpoint]}});break;case"none":n=e9.Hq();break;default:throw Error("unsupported client authentication method")}let p=[],h=await tn.use(t,p,r);try{a=e9.S7(i,d,new URLSearchParams(e),c.checks.includes("state")?h:e9.ey)}catch(e){if(e instanceof e9.GF){let t={providerId:c.id,...Object.fromEntries(e.cause.entries())};throw s.debug("OAuthCallbackError",t),new C("OAuth Provider returned an error",t)}throw e}let f=await tr.use(t,p,r),m=c.callbackUrl;!r.isOnRedirectProxy&&c.redirectProxyUrl&&(m=c.redirectProxyUrl);let g=c.token?.additionalParametersKeys;if(g){let t=Array.from(new URLSearchParams(e).entries()).filter(([e])=>g.includes(e));o=new URLSearchParams(t)}let w=await e9.Oy(i,d,n,a,m,f??"decoy",{[e9.TZ]:!0,[e9.rK]:(...e)=>(c.checks.includes("pkce")||e[1].body.delete("code_verifier"),(c[eW]??fetch)(...e)),additionalParameters:o});c.token?.conform&&(w=await c.token.conform(w.clone())??w);let y={},b="oidc"===c.type;if(c[eV])switch(c.id){case"microsoft-entra-id":case"azure-ad":{let{tid:e}=(0,tc.t)((await w.clone().json()).id_token);if("string"==typeof e){let t=i.issuer?.match(/microsoftonline\.com\/(\w+)\/v2\.0/)?.[1]??"common",r=new URL(i.issuer.replace(t,e)),n=await e9.FC(r,{[e9.rK]:c[eW]});i=await e9.hS(r,n)}}}let v=await e9.kM(i,d,w,{expectedNonce:await ta.use(t,p,r),requireIdToken:b});if(b){let t=e9._M(v);if(y=t,c[eV]&&"apple"===c.id)try{y.user=JSON.parse(e?.user)}catch{}if(!1===c.idToken){let e=await e9.u6(i,d,v.access_token,{[e9.rK]:c[eW],[e9.TZ]:!0});y=await e9.Zu(i,d,t.sub,e)}}else if(u?.request){let e=await u.request({tokens:v,provider:c});e instanceof Object&&(y=e)}else if(u?.url){let e=await e9.u6(i,d,v.access_token,{[e9.rK]:c[eW],[e9.TZ]:!0});y=await e.json()}else throw TypeError("No userinfo endpoint configured");return v.expires_in&&(v.expires_at=Math.floor(Date.now()/1e3)+Number(v.expires_in)),{...await td(y,c,v,s),profile:y,cookies:p}}async function td(e,t,r,i){try{let i=await t.profile(e,r);return{user:{...i,id:crypto.randomUUID(),email:i.email?.toLowerCase()},account:{...r,provider:t.id,type:t.type,providerAccountId:i.id??crypto.randomUUID()}}}catch(r){i.debug("getProfile error details",e),i.error(new E(r,{provider:t.id}))}}async function tp(e,t,r,i){let n=await tw(e,t,r),{cookie:a}=await ts.create(e,n.challenge,r);return{status:200,cookies:[...i??[],a],body:{action:"register",options:n},headers:{"Content-Type":"application/json"}}}async function th(e,t,r,i){let n=await tg(e,t,r),{cookie:a}=await ts.create(e,n.challenge);return{status:200,cookies:[...i??[],a],body:{action:"authenticate",options:n},headers:{"Content-Type":"application/json"}}}async function tf(e,t,r){let i;let{adapter:n,provider:a}=e,o=t.body&&"string"==typeof t.body.data?JSON.parse(t.body.data):void 0;if(!o||"object"!=typeof o||!("id"in o)||"string"!=typeof o.id)throw new f("Invalid WebAuthn Authentication response");let s=tv(tb(o.id)),c=await n.getAuthenticator(s);if(!c)throw new f(`WebAuthn authenticator not found in database: ${JSON.stringify({credentialID:s})}`);let{challenge:l}=await ts.use(e,t.cookies,r);try{let r=a.getRelayingParty(e,t);i=await a.simpleWebAuthn.verifyAuthenticationResponse({...a.verifyAuthenticationOptions,expectedChallenge:l,response:o,authenticator:{...c,credentialDeviceType:c.credentialDeviceType,transports:tk(c.transports),credentialID:tb(c.credentialID),credentialPublicKey:tb(c.credentialPublicKey)},expectedOrigin:r.origin,expectedRPID:r.id})}catch(e){throw new M(e)}let{verified:u,authenticationInfo:d}=i;if(!u)throw new M("WebAuthn authentication response could not be verified");try{let{newCounter:e}=d;await n.updateAuthenticatorCounter(c.credentialID,e)}catch(e){throw new g(`Failed to update authenticator counter. This may cause future authentication attempts to fail. ${JSON.stringify({credentialID:s,oldCounter:c.counter,newCounter:d.newCounter})}`,e)}let p=await n.getAccount(c.providerAccountId,a.id);if(!p)throw new f(`WebAuthn account not found in database: ${JSON.stringify({credentialID:s,providerAccountId:c.providerAccountId})}`);let h=await n.getUser(p.userId);if(!h)throw new f(`WebAuthn user not found in database: ${JSON.stringify({credentialID:s,providerAccountId:c.providerAccountId,userID:p.userId})}`);return{account:p,user:h}}async function tm(e,t,r){var i;let n;let{provider:a}=e,o=t.body&&"string"==typeof t.body.data?JSON.parse(t.body.data):void 0;if(!o||"object"!=typeof o||!("id"in o)||"string"!=typeof o.id)throw new f("Invalid WebAuthn Registration response");let{challenge:s,registerData:c}=await ts.use(e,t.cookies,r);if(!c)throw new f("Missing user registration data in WebAuthn challenge cookie");try{let r=a.getRelayingParty(e,t);n=await a.simpleWebAuthn.verifyRegistrationResponse({...a.verifyRegistrationOptions,expectedChallenge:s,response:o,expectedOrigin:r.origin,expectedRPID:r.id})}catch(e){throw new M(e)}if(!n.verified||!n.registrationInfo)throw new M("WebAuthn registration response could not be verified");let l={providerAccountId:tv(n.registrationInfo.credentialID),provider:e.provider.id,type:a.type},u={providerAccountId:l.providerAccountId,counter:n.registrationInfo.counter,credentialID:tv(n.registrationInfo.credentialID),credentialPublicKey:tv(n.registrationInfo.credentialPublicKey),credentialBackedUp:n.registrationInfo.credentialBackedUp,credentialDeviceType:n.registrationInfo.credentialDeviceType,transports:(i=o.response.transports,i?.join(","))};return{user:c,account:l,authenticator:u}}async function tg(e,t,r){let{provider:i,adapter:n}=e,a=r&&r.id?await n.listAuthenticatorsByUserId(r.id):null,o=i.getRelayingParty(e,t);return await i.simpleWebAuthn.generateAuthenticationOptions({...i.authenticationOptions,rpID:o.id,allowCredentials:a?.map(e=>({id:tb(e.credentialID),type:"public-key",transports:tk(e.transports)}))})}async function tw(e,t,r){let{provider:i,adapter:n}=e,a=r.id?await n.listAuthenticatorsByUserId(r.id):null,o=eN(32),s=i.getRelayingParty(e,t);return await i.simpleWebAuthn.generateRegistrationOptions({...i.registrationOptions,userID:o,userName:r.email,userDisplayName:r.name??void 0,rpID:s.id,rpName:s.name,excludeCredentials:a?.map(e=>({id:tb(e.credentialID),type:"public-key",transports:tk(e.transports)}))})}function ty(e){let{provider:t,adapter:r}=e;if(!r)throw new S("An adapter is required for the WebAuthn provider");if(!t||"webauthn"!==t.type)throw new q("Provider must be WebAuthn");return{...e,provider:t,adapter:r}}function tb(e){return new Uint8Array(Buffer.from(e,"base64"))}function tv(e){return Buffer.from(e).toString("base64")}function tk(e){return e?e.split(","):void 0}async function tx(e,t,r,i){if(!t.provider)throw new q("Callback route called without provider");let{query:n,body:a,method:o,headers:s}=e,{provider:c,adapter:l,url:u,callbackUrl:d,pages:p,jwt:h,events:m,callbacks:g,session:{strategy:w,maxAge:b},logger:v}=t,k="jwt"===w;try{if("oauth"===c.type||"oidc"===c.type){let o;let s=c.authorization?.url.searchParams.get("response_mode")==="form_post"?a:n;if(t.isOnRedirectProxy&&s?.state){let e=await tn.decode(s.state,t);if(e?.origin&&new URL(e.origin).origin!==t.url.origin){let t=`${e.origin}?${new URLSearchParams(s)}`;return v.debug("Proxy redirecting to",t),{redirect:t,cookies:i}}}let f=await tu(s,e.cookies,t);f.cookies.length&&i.push(...f.cookies),v.debug("authorization result",f);let{user:w,account:y,profile:x}=f;if(!w||!y||!x)return{redirect:`${u}/signin`,cookies:i};if(l){let{getUserByAccount:e}=l;o=await e({providerAccountId:y.providerAccountId,provider:c.id})}let U=await tU({user:o??w,account:y,profile:x},t);if(U)return{redirect:U,cookies:i};let{user:$,session:T,isNewUser:S}=await e4(r.value,w,y,t);if(k){let e={name:$.name,email:$.email,picture:$.image,sub:$.id?.toString()},n=await g.jwt({token:e,user:$,account:y,profile:x,isNewUser:S,trigger:S?"signUp":"signIn"});if(null===n)i.push(...r.clean());else{let e=t.cookies.sessionToken.name,a=await h.encode({...h,token:n,salt:e}),o=new Date;o.setTime(o.getTime()+1e3*b);let s=r.chunk(a,{expires:o});i.push(...s)}}else i.push({name:t.cookies.sessionToken.name,value:T.sessionToken,options:{...t.cookies.sessionToken.options,expires:T.expires}});if(await m.signIn?.({user:$,account:y,profile:x,isNewUser:S}),S&&p.newUser)return{redirect:`${p.newUser}${p.newUser.includes("?")?"&":"?"}${new URLSearchParams({callbackUrl:d})}`,cookies:i};return{redirect:d,cookies:i}}if("email"===c.type){let e=n?.token,a=n?.email;if(!e){let t=TypeError("Missing token. The sign-in URL was manually opened without token or the link was not sent correctly in the email.",{cause:{hasToken:!!e}});throw t.name="Configuration",t}let o=c.secret??t.secret,s=await l.useVerificationToken({identifier:a,token:await eL(`${e}${o}`)}),u=!!s,f=u&&s.expires.valueOf()<Date.now();if(!u||f||a&&s.identifier!==a)throw new Z({hasInvite:u,expired:f});let{identifier:w}=s,y=await l.getUserByEmail(w)??{id:crypto.randomUUID(),email:w,emailVerified:null},v={providerAccountId:y.email,userId:y.id,type:"email",provider:c.id},x=await tU({user:y,account:v},t);if(x)return{redirect:x,cookies:i};let{user:U,session:$,isNewUser:T}=await e4(r.value,y,v,t);if(k){let e={name:U.name,email:U.email,picture:U.image,sub:U.id?.toString()},n=await g.jwt({token:e,user:U,account:v,isNewUser:T,trigger:T?"signUp":"signIn"});if(null===n)i.push(...r.clean());else{let e=t.cookies.sessionToken.name,a=await h.encode({...h,token:n,salt:e}),o=new Date;o.setTime(o.getTime()+1e3*b);let s=r.chunk(a,{expires:o});i.push(...s)}}else i.push({name:t.cookies.sessionToken.name,value:$.sessionToken,options:{...t.cookies.sessionToken.options,expires:$.expires}});if(await m.signIn?.({user:U,account:v,isNewUser:T}),T&&p.newUser)return{redirect:`${p.newUser}${p.newUser.includes("?")?"&":"?"}${new URLSearchParams({callbackUrl:d})}`,cookies:i};return{redirect:d,cookies:i}}if("credentials"===c.type&&"POST"===o){let e=a??{};Object.entries(n??{}).forEach(([e,t])=>u.searchParams.set(e,t));let l=await c.authorize(e,new Request(u,{headers:s,method:o,body:JSON.stringify(a)}));if(l)l.id=l.id?.toString()??crypto.randomUUID();else throw new x;let p={providerAccountId:l.id,type:"credentials",provider:c.id},f=await tU({user:l,account:p,credentials:e},t);if(f)return{redirect:f,cookies:i};let w={name:l.name,email:l.email,picture:l.image,sub:l.id},y=await g.jwt({token:w,user:l,account:p,isNewUser:!1,trigger:"signIn"});if(null===y)i.push(...r.clean());else{let e=t.cookies.sessionToken.name,n=await h.encode({...h,token:y,salt:e}),a=new Date;a.setTime(a.getTime()+1e3*b);let o=r.chunk(n,{expires:a});i.push(...o)}return await m.signIn?.({user:l,account:p}),{redirect:d,cookies:i}}if("webauthn"===c.type&&"POST"===o){let n,a,o;let s=e.body?.action;if("string"!=typeof s||"authenticate"!==s&&"register"!==s)throw new f("Invalid action parameter");let c=ty(t);switch(s){case"authenticate":{let t=await tf(c,e,i);n=t.user,a=t.account;break}case"register":{let r=await tm(t,e,i);n=r.user,a=r.account,o=r.authenticator}}await tU({user:n,account:a},t);let{user:l,isNewUser:u,session:w,account:y}=await e4(r.value,n,a,t);if(!y)throw new f("Error creating or finding account");if(o&&l.id&&await c.adapter.createAuthenticator({...o,userId:l.id}),k){let e={name:l.name,email:l.email,picture:l.image,sub:l.id?.toString()},n=await g.jwt({token:e,user:l,account:y,isNewUser:u,trigger:u?"signUp":"signIn"});if(null===n)i.push(...r.clean());else{let e=t.cookies.sessionToken.name,a=await h.encode({...h,token:n,salt:e}),o=new Date;o.setTime(o.getTime()+1e3*b);let s=r.chunk(a,{expires:o});i.push(...s)}}else i.push({name:t.cookies.sessionToken.name,value:w.sessionToken,options:{...t.cookies.sessionToken.options,expires:w.expires}});if(await m.signIn?.({user:l,account:y,isNewUser:u}),u&&p.newUser)return{redirect:`${p.newUser}${p.newUser.includes("?")?"&":"?"}${new URLSearchParams({callbackUrl:d})}`,cookies:i};return{redirect:d,cookies:i}}throw new q(`Callback for provider type (${c.type}) is not supported`)}catch(t){if(t instanceof f)throw t;let e=new y(t,{provider:c.id});throw v.debug("callback route error details",{method:o,query:n,body:a}),e}}async function tU(e,t){let r;let{signIn:i,redirect:n}=t.callbacks;try{r=await i(e)}catch(e){if(e instanceof f)throw e;throw new w(e)}if(!r)throw new w("AccessDenied");if("string"==typeof r)return await n({url:r,baseUrl:t.url.origin})}async function t$(e,t,r,i,n){let{adapter:a,jwt:o,events:s,callbacks:c,logger:l,session:{strategy:u,maxAge:d}}=e,p={body:null,headers:{"Content-Type":"application/json"},cookies:r},h=t.value;if(!h)return p;if("jwt"===u){try{let r=e.cookies.sessionToken.name,a=await o.decode({...o,token:h,salt:r});if(!a)throw Error("Invalid JWT");let l=await c.jwt({token:a,...i&&{trigger:"update"},session:n}),u=e6(d);if(null!==l){let e={user:{name:l.name,email:l.email,image:l.picture},expires:u.toISOString()},i=await c.session({session:e,token:l});p.body=i;let n=await o.encode({...o,token:l,salt:r}),a=t.chunk(n,{expires:u});p.cookies?.push(...a),await s.session?.({session:i,token:l})}else p.cookies?.push(...t.clean())}catch(e){l.error(new T(e)),p.cookies?.push(...t.clean())}return p}try{let{getSessionAndUser:r,deleteSession:o,updateSession:l}=a,u=await r(h);if(u&&u.session.expires.valueOf()<Date.now()&&(await o(h),u=null),u){let{user:t,session:r}=u,a=e.session.updateAge,o=r.expires.valueOf()-1e3*d+1e3*a,f=e6(d);o<=Date.now()&&await l({sessionToken:h,expires:f});let m=await c.session({session:{...r,user:t},user:t,newSession:n,...i?{trigger:"update"}:{}});p.body=m,p.cookies?.push({name:e.cookies.sessionToken.name,value:h,options:{...e.cookies.sessionToken.options,expires:f}}),await s.session?.({session:m})}else h&&p.cookies?.push(...t.clean())}catch(e){l.error(new P(e))}return p}async function tT(e,t){let r,i;let{logger:n,provider:a}=t,o=a.authorization?.url;if(!o||"authjs.dev"===o.host){let e=new URL(a.issuer),t=await e9.FC(e,{[e9.rK]:a[eW],[e9.TZ]:!0}),r=await e9.hS(e,t).catch(t=>{if(!(t instanceof TypeError)||"Invalid URL"!==t.message)throw t;throw TypeError(`Discovery request responded with an invalid issuer. expected: ${e}`)});if(!r.authorization_endpoint)throw TypeError("Authorization server did not provide an authorization endpoint.");o=new URL(r.authorization_endpoint)}let s=o.searchParams,c=a.callbackUrl;!t.isOnRedirectProxy&&a.redirectProxyUrl&&(c=a.redirectProxyUrl,i=a.callbackUrl,n.debug("using redirect proxy",{redirect_uri:c,data:i}));let l=Object.assign({response_type:"code",client_id:a.clientId,redirect_uri:c,...a.authorization?.params},Object.fromEntries(a.authorization?.url.searchParams??[]),e);for(let e in l)s.set(e,l[e]);let u=[];a.authorization?.url.searchParams.get("response_mode")==="form_post"&&(t.cookies.state.options.sameSite="none",t.cookies.state.options.secure=!0,t.cookies.nonce.options.sameSite="none",t.cookies.nonce.options.secure=!0);let d=await tn.create(t,i);if(d&&(s.set("state",d.value),u.push(d.cookie)),a.checks?.includes("pkce")){if(r&&!r.code_challenge_methods_supported?.includes("S256"))"oidc"===a.type&&(a.checks=["nonce"]);else{let{value:e,cookie:r}=await tr.create(t);s.set("code_challenge",e),s.set("code_challenge_method","S256"),u.push(r)}}let p=await ta.create(t);return p&&(s.set("nonce",p.value),u.push(p.cookie)),"oidc"!==a.type||o.searchParams.has("scope")||o.searchParams.set("scope","openid profile email"),n.debug("authorization url is ready",{url:o,cookies:u,provider:a}),{redirect:o.toString(),cookies:u}}async function tS(e,t){let r;let{body:i}=e,{provider:n,callbacks:a,adapter:o}=t,s=(n.normalizeIdentifier??function(e){if(!e)throw Error("Missing email from request body.");let[t,r]=e.toLowerCase().trim().split("@");return r=r.split(",")[0],`${t}@${r}`})(i?.email),c={id:crypto.randomUUID(),email:s,emailVerified:null},l=await o.getUserByEmail(s)??c,u={providerAccountId:s,userId:l.id,type:"email",provider:n.id};try{r=await a.signIn({user:l,account:u,email:{verificationRequest:!0}})}catch(e){throw new w(e)}if(!r)throw new w("AccessDenied");if("string"==typeof r)return{redirect:await a.redirect({url:r,baseUrl:t.url.origin})};let{callbackUrl:d,theme:p}=t,h=await n.generateVerificationToken?.()??eN(32),f=new Date(Date.now()+(n.maxAge??86400)*1e3),m=n.secret??t.secret,g=new URL(t.basePath,t.url.origin),y=n.sendVerificationRequest({identifier:s,token:h,expires:f,url:`${g}/callback/${n.id}?${new URLSearchParams({callbackUrl:d,token:h,email:s})}`,provider:n,theme:p,request:new Request(e.url,{headers:e.headers,method:e.method,body:"POST"===e.method?JSON.stringify(e.body??{}):void 0})}),b=o.createVerificationToken?.({identifier:s,token:await eL(`${h}${m}`),expires:f});return await Promise.all([y,b]),{redirect:`${g}/verify-request?${new URLSearchParams({provider:n.id,type:n.type})}`}}async function tA(e,t,r){let i=`${r.url.origin}${r.basePath}/signin`;if(!r.provider)return{redirect:i,cookies:t};switch(r.provider.type){case"oauth":case"oidc":{let{redirect:i,cookies:n}=await tT(e.query,r);return n&&t.push(...n),{redirect:i,cookies:t}}case"email":return{...await tS(e,r),cookies:t};default:return{redirect:i,cookies:t}}}async function t_(e,t,r){let{jwt:i,events:n,callbackUrl:a,logger:o,session:s}=r,c=t.value;if(!c)return{redirect:a,cookies:e};try{if("jwt"===s.strategy){let e=r.cookies.sessionToken.name,t=await i.decode({...i,token:c,salt:e});await n.signOut?.({token:t})}else{let e=await r.adapter?.deleteSession(c);await n.signOut?.({session:e})}}catch(e){o.error(new L(e))}return e.push(...t.clean()),{redirect:a,cookies:e}}async function tI(e,t){let{adapter:r,jwt:i,session:{strategy:n}}=e,a=t.value;if(!a)return null;if("jwt"===n){let t=e.cookies.sessionToken.name,r=await i.decode({...i,token:a,salt:t});if(r&&r.sub)return{id:r.sub,name:r.name,email:r.email,image:r.picture}}else{let e=await r?.getSessionAndUser(a);if(e)return e.user}return null}async function tR(e,t,r,i){let n=ty(t),{provider:a}=n,{action:o}=e.query??{};if("register"!==o&&"authenticate"!==o&&void 0!==o)return{status:400,body:{error:"Invalid action"},cookies:i,headers:{"Content-Type":"application/json"}};let s=await tI(t,r),c=s?{user:s,exists:!0}:await a.getUserInfo(t,e),l=c?.user;switch(function(e,t,r){let{user:i,exists:n=!1}=r??{};switch(e){case"authenticate":return"authenticate";case"register":if(i&&t===n)return"register";break;case void 0:if(!t){if(!i||n)return"authenticate";return"register"}}return null}(o,!!s,c)){case"authenticate":return th(n,e,l,i);case"register":if("string"==typeof l?.email)return tp(n,e,l,i);break;default:return{status:400,body:{error:"Invalid request"},cookies:i,headers:{"Content-Type":"application/json"}}}}async function tC(e,t){let{action:r,providerId:i,error:n,method:a}=e,o=t.skipCSRFCheck===ez,{options:s,cookies:c}=await eG({authOptions:t,action:r,providerId:i,url:e.url,callbackUrl:e.body?.callbackUrl??e.query?.callbackUrl,csrfToken:e.body?.csrfToken,cookies:e.cookies,isPost:"POST"===a,csrfDisabled:o}),l=new h(s.cookies.sessionToken,e.cookies,s.logger);if("GET"===a){let t=e3({...s,query:e.query,cookies:c});switch(r){case"callback":return await tx(e,s,l,c);case"csrf":return t.csrf(o,s,c);case"error":return t.error(n);case"providers":return t.providers(s.providers);case"session":return await t$(s,l,c);case"signin":return t.signin(i,n);case"signout":return t.signout();case"verify-request":return t.verifyRequest();case"webauthn-options":return await tR(e,s,l,c)}}else{let{csrfTokenVerified:t}=s;switch(r){case"callback":return"credentials"===s.provider.type&&eq(r,t),await tx(e,s,l,c);case"session":return eq(r,t),await t$(s,l,c,!0,e.body?.data);case"signin":return eq(r,t),await tA(e,c,s);case"signout":return eq(r,t),await t_(c,l,s)}}throw new N(`Cannot handle action: ${r}`)}function tE(e,t,r,i,n){let a;let o=n?.basePath,s=i.AUTH_URL??i.NEXTAUTH_URL;if(s)a=new URL(s),o&&"/"!==o&&"/"!==a.pathname&&(a.pathname!==o&&eI(n).warn("env-url-basepath-mismatch"),a.pathname="/");else{let e=r.get("x-forwarded-host")??r.get("host"),i=r.get("x-forwarded-proto")??t??"https",n=i.endsWith(":")?i:i+":";a=new URL(`${n}//${e}`)}let c=a.toString().replace(/\/$/,"");if(o){let t=o?.replace(/(^\/|\/$)/g,"")??"";return new URL(`${c}/${t}/${e}`)}return new URL(`${c}/${e}`)}async function tP(e,t){let r=eI(t),i=await eO(e,t);if(!i)return Response.json("Bad request.",{status:400});let n=function(e,t){let{url:r}=e,i=[];if(!K&&t.debug&&i.push("debug-enabled"),!t.trustHost)return new B(`Host must be trusted. URL was: ${e.url}`);if(!t.secret?.length)return new I("Please define a `secret`");let n=e.query?.callbackUrl;if(n&&!J(n,r.origin))return new k(`Invalid callback URL. Received: ${n}`);let{callbackUrl:a}=p(t.useSecureCookies??"https:"===r.protocol),o=e.cookies?.[t.cookies?.callbackUrl?.name??a.name];if(o&&!J(o,r.origin))return new k(`Invalid callback URL. Received: ${o}`);let s=!1;for(let e of t.providers){let t="function"==typeof e?e():e;if(("oauth"===t.type||"oidc"===t.type)&&!(t.issuer??t.options?.issuer)){let e;let{authorization:r,token:i,userinfo:n}=t;if("string"==typeof r||r?.url?"string"==typeof i||i?.url?"string"==typeof n||n?.url||(e="userinfo"):e="token":e="authorization",e)return new U(`Provider "${t.id}" is missing both \`issuer\` and \`${e}\` endpoint config. At least one of them is required`)}if("credentials"===t.type)G=!0;else if("email"===t.type)Y=!0;else if("webauthn"===t.type){var c;if(Q=!0,t.simpleWebAuthnBrowserVersion&&(c=t.simpleWebAuthnBrowserVersion,!/^v\d+(?:\.\d+){0,2}$/.test(c)))return new f(`Invalid provider config for "${t.id}": simpleWebAuthnBrowserVersion "${t.simpleWebAuthnBrowserVersion}" must be a valid semver string.`);if(t.enableConditionalUI){if(s)return new W("Multiple webauthn providers have 'enableConditionalUI' set to True. Only one provider can have this option enabled at a time");if(s=!0,!Object.values(t.formFields).some(e=>e.autocomplete&&e.autocomplete.toString().indexOf("webauthn")>-1))return new V(`Provider "${t.id}" has 'enableConditionalUI' set to True, but none of its formFields have 'webauthn' in their autocomplete param`)}}}if(G){let e=t.session?.strategy==="database",r=!t.providers.some(e=>"credentials"!==("function"==typeof e?e():e).type);if(e&&r)return new D("Signing in with credentials only supported if JWT strategy is enabled");if(t.providers.some(e=>{let t="function"==typeof e?e():e;return"credentials"===t.type&&!t.authorize}))return new _("Must define an authorize() handler to use credentials authentication provider")}let{adapter:l,session:u}=t,d=[];if(Y||u?.strategy==="database"||!u?.strategy&&l){if(Y){if(!l)return new S("Email login requires an adapter");d.push(...ee)}else{if(!l)return new S("Database session requires an adapter");d.push(...et)}}if(Q){if(!t.experimental?.enableWebAuthn)return new X("WebAuthn is an experimental feature. To enable it, set `experimental.enableWebAuthn` to `true` in your config");if(i.push("experimental-webauthn"),!l)return new S("WebAuthn requires an adapter");d.push(...er)}if(l){let e=d.filter(e=>!(e in l));if(e.length)return new A(`Required adapter methods were missing: ${e.join(", ")}`)}return K||(K=!0),i}(i,t);if(Array.isArray(n))n.forEach(r.warn);else if(n){if(r.error(n),!new Set(["signin","signout","error","verify-request"]).has(i.action)||"GET"!==i.method)return Response.json({message:"There was a problem with the server configuration. Check the server logs for more information."},{status:500});let{pages:e,theme:a}=t,o=e?.error&&i.url.searchParams.get("callbackUrl")?.startsWith(e.error);if(!e?.error||o)return o&&r.error(new b(`The error page ${e?.error} should not require authentication`)),ej(e3({theme:a}).error("Configuration"));let s=`${i.url.origin}${e.error}?error=Configuration`;return Response.redirect(s)}let a=e.headers?.has("X-Auth-Return-Redirect"),o=t.raw===eH;try{let e=await tC(i,t);if(o)return e;let r=ej(e),n=r.headers.get("Location");if(!a||!n)return r;return Response.json({url:n},{headers:r.headers})}catch(d){r.error(d);let n=d instanceof f;if(n&&o&&!a)throw d;if("POST"===e.method&&"session"===i.action)return Response.json(null,{status:400});let s=new URLSearchParams({error:d instanceof f&&H.has(d.type)?d.type:"Configuration"});d instanceof x&&s.set("code",d.code);let c=n&&d.kind||"error",l=t.pages?.[c]??`${t.basePath}/${c.toLowerCase()}`,u=`${i.url.origin}${l}?${s}`;if(a)return Response.json({url:u});return Response.redirect(u)}}var tO=r(92824);function tj(e){let t=process.env.AUTH_URL??process.env.NEXTAUTH_URL;if(!t)return e;let{origin:r}=new URL(t),{href:i,origin:n}=e.nextUrl;return new tO.NextRequest(i.replace(n,r),e)}function tL(e){try{e.secret??(e.secret=process.env.AUTH_SECRET??process.env.NEXTAUTH_SECRET);let t=process.env.AUTH_URL??process.env.NEXTAUTH_URL;if(!t)return;let{pathname:r}=new URL(t);if("/"===r)return;e.basePath||(e.basePath=r)}catch{}finally{e.basePath||(e.basePath="/api/auth"),function(e,t,r=!1){try{let i=e.AUTH_URL;i&&(t.basePath?r||eI(t).warn("env-url-basepath-redundant"):t.basePath=new URL(i).pathname)}catch{}finally{t.basePath??(t.basePath="/auth")}if(!t.secret?.length){t.secret=[];let r=e.AUTH_SECRET;for(let i of(r&&t.secret.push(r),[1,2,3])){let r=e[`AUTH_SECRET_${i}`];r&&t.secret.unshift(r)}}t.redirectProxyUrl??(t.redirectProxyUrl=e.AUTH_REDIRECT_PROXY_URL),t.trustHost??(t.trustHost=!!(e.AUTH_URL??e.AUTH_TRUST_HOST??e.VERCEL??e.CF_PAGES??"production"!==e.NODE_ENV)),t.providers=t.providers.map(t=>{let{id:r}="function"==typeof t?t({}):t,i=r.toUpperCase().replace(/-/g,"_"),n=e[`AUTH_${i}_ID`],a=e[`AUTH_${i}_SECRET`],o=e[`AUTH_${i}_ISSUER`],s=e[`AUTH_${i}_KEY`],c="function"==typeof t?t({clientId:n,clientSecret:a,issuer:o,apiKey:s}):t;return"oauth"===c.type||"oidc"===c.type?(c.clientId??(c.clientId=n),c.clientSecret??(c.clientSecret=a),c.issuer??(c.issuer=o)):"email"===c.type&&(c.apiKey??(c.apiKey=s)),c})}(process.env,e,!0)}}var tN=r(19674);async function tD(e,t){return tP(new Request(tE("session",e.get("x-forwarded-proto"),e,process.env,t),{headers:{cookie:e.get("cookie")??""}}),{...t,callbacks:{...t.callbacks,async session(...e){let r=await t.callbacks?.session?.(...e)??{...e[0].session,expires:e[0].session.expires?.toISOString?.()??e[0].session.expires};return{user:e[0].user??e[0].token,...r}}}})}function tq(e){return"function"==typeof e}function tB(e,t){return"function"==typeof e?async(...r)=>{if(!r.length){let r=await (0,tN.headers)(),i=await e(void 0);return t?.(i),tD(r,i).then(e=>e.json())}if(r[0]instanceof Request){let i=r[0],n=r[1],a=await e(i);return t?.(a),tZ([i,n],a)}if(tq(r[0])){let i=r[0];return async(...r)=>{let n=await e(r[0]);return t?.(n),tZ(r,n,i)}}let i="req"in r[0]?r[0].req:r[0],n="res"in r[0]?r[0].res:r[1],a=await e(i);return t?.(a),tD(new Headers(i.headers),a).then(async e=>{let t=await e.json();for(let t of e.headers.getSetCookie())"headers"in n?n.headers.append("set-cookie",t):n.appendHeader("set-cookie",t);return t})}:(...t)=>{if(!t.length)return Promise.resolve((0,tN.headers)()).then(t=>tD(t,e).then(e=>e.json()));if(t[0]instanceof Request)return tZ([t[0],t[1]],e);if(tq(t[0])){let r=t[0];return async(...t)=>tZ(t,e,r).then(e=>e)}let r="req"in t[0]?t[0].req:t[0],i="res"in t[0]?t[0].res:t[1];return tD(new Headers(r.headers),e).then(async e=>{let t=await e.json();for(let t of e.headers.getSetCookie())"headers"in i?i.headers.append("set-cookie",t):i.appendHeader("set-cookie",t);return t})}}async function tZ(e,t,r){let i=tj(e[0]),n=await tD(i.headers,t),a=await n.json(),o=!0;t.callbacks?.authorized&&(o=await t.callbacks.authorized({request:i,auth:a}));let s=tO.NextResponse.next?.();if(o instanceof Response){s=o;let e=o.headers.get("Location"),{pathname:r}=i.nextUrl;e&&function(e,t,r){let i=t.replace(`${e}/`,""),n=Object.values(r.pages??{});return(tz.has(i)||n.includes(t))&&t===e}(r,new URL(e).pathname,t)&&(o=!0)}else if(r)i.auth=a,s=await r(i,e[1])??tO.NextResponse.next();else if(!o){let e=t.pages?.signIn??`${t.basePath}/signin`;if(i.nextUrl.pathname!==e){let t=i.nextUrl.clone();t.pathname=e,t.searchParams.set("callbackUrl",i.nextUrl.href),s=tO.NextResponse.redirect(t)}}let c=new Response(s?.body,s);for(let e of n.headers.getSetCookie())c.headers.append("set-cookie",e);return c}let tz=new Set(["providers","session","csrf","signin","signout","callback","verify-request","error"]);var tH=r(59405);async function tW(e,t={},r,i){let n=new Headers(await (0,tN.headers)()),{redirect:a=!0,redirectTo:o,...s}=t instanceof FormData?Object.fromEntries(t):t,c=o?.toString()??n.get("Referer")??"/",l=tE("signin",n.get("x-forwarded-proto"),n,process.env,i);if(!e)return l.searchParams.append("callbackUrl",c),a&&(0,tH.redirect)(l.toString()),l.toString();let u=`${l}/${e}?${new URLSearchParams(r)}`,d={};for(let t of i.providers){let{options:r,...i}="function"==typeof t?t():t,n=r?.id??i.id;if(n===e){d={id:n,type:r?.type??i.type};break}}if(!d.id){let e=`${l}?${new URLSearchParams({callbackUrl:c})}`;return a&&(0,tH.redirect)(e),e}"credentials"===d.type&&(u=u.replace("signin","callback")),n.set("Content-Type","application/x-www-form-urlencoded");let p=new Request(u,{method:"POST",headers:n,body:new URLSearchParams({...s,callbackUrl:c})}),h=await tP(p,{...i,raw:eH,skipCSRFCheck:ez}),f=await (0,tN.cookies)();for(let e of h?.cookies??[])f.set(e.name,e.value,e.options);let m=(h instanceof Response?h.headers.get("Location"):h.redirect)??u;return a?(0,tH.redirect)(m):m}async function tV(e,t){let r=new Headers(await (0,tN.headers)());r.set("Content-Type","application/x-www-form-urlencoded");let i=tE("signout",r.get("x-forwarded-proto"),r,process.env,t),n=new URLSearchParams({callbackUrl:e?.redirectTo??r.get("Referer")??"/"}),a=new Request(i,{method:"POST",headers:r,body:n}),o=await tP(a,{...t,raw:eH,skipCSRFCheck:ez}),s=await (0,tN.cookies)();for(let e of o?.cookies??[])s.set(e.name,e.value,e.options);return e?.redirect??!0?(0,tH.redirect)(o.redirect):o}async function tM(e,t){let r=new Headers(await (0,tN.headers)());r.set("Content-Type","application/json");let i=new Request(tE("session",r.get("x-forwarded-proto"),r,process.env,t),{method:"POST",headers:r,body:JSON.stringify({data:e})}),n=await tP(i,{...t,raw:eH,skipCSRFCheck:ez}),a=await (0,tN.cookies)();for(let e of n?.cookies??[])a.set(e.name,e.value,e.options);return n.body}let{handlers:tF,auth:tX,signIn:tK,signOut:tJ,unstable_update:tG}=function(e){if("function"==typeof e){let t=async t=>{let r=await e(t);return tL(r),tP(tj(t),r)};return{handlers:{GET:t,POST:t},auth:tB(e,e=>tL(e)),signIn:async(t,r,i)=>{let n=await e(void 0);return tL(n),tW(t,r,i,n)},signOut:async t=>{let r=await e(void 0);return tL(r),tV(t,r)},unstable_update:async t=>{let r=await e(void 0);return tL(r),tM(t,r)}}}tL(e);let t=t=>tP(tj(t),e);return{handlers:{GET:t,POST:t},auth:tB(e),signIn:(t,r,i)=>tW(t,r,i,e),signOut:t=>tV(t,e),unstable_update:t=>tM(t,e)}}({debug:!0,providers:[{id:"credentials",name:"Credentials",type:"credentials",credentials:{},authorize:()=>null,options:{credentials:{password:{label:"Password",type:"password"}},authorize:e=>"password"!==e.password?null:{id:"test",name:"Test User",email:"test@example.com"}}},function(e){let t=e?.enterprise?.baseUrl??"https://github.com",r=e?.enterprise?.baseUrl?`${e?.enterprise?.baseUrl}/api/v3`:"https://api.github.com";return{id:"github",name:"GitHub",type:"oauth",authorization:{url:`${t}/login/oauth/authorize`,params:{scope:"read:user user:email"}},token:`${t}/login/oauth/access_token`,userinfo:{url:`${r}/user`,async request({tokens:e,provider:t}){let i=await fetch(t.userinfo?.url,{headers:{Authorization:`Bearer ${e.access_token}`,"User-Agent":"authjs"}}).then(async e=>await e.json());if(!i.email){let t=await fetch(`${r}/user/emails`,{headers:{Authorization:`Bearer ${e.access_token}`,"User-Agent":"authjs"}});if(t.ok){let e=await t.json();i.email=(e.find(e=>e.primary)??e[0]).email}}return i}},profile:e=>({id:e.id.toString(),name:e.name??e.login,email:e.email,image:e.avatar_url}),style:{bg:"#24292f",text:"#fff"},options:e}},function(e){return{id:"keycloak",name:"Keycloak",type:"oidc",style:{brandColor:"#428bca"},options:e}}],callbacks:{jwt:({token:e,trigger:t,session:r})=>("update"===t&&(e.name=r.user.name),e)},basePath:"/auth",session:{strategy:"jwt"}})}};