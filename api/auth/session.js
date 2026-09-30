const crypto=require("crypto");
function json(res,s,b){res.statusCode=s;res.setHeader("Content-Type","application/json");res.end(JSON.stringify(b))}
module.exports=(req,res)=>{
 const cookies=Object.fromEntries(String(req.headers.cookie||"").split(";").map(x=>x.trim().split("=")).filter(x=>x.length===2));
 const raw=cookies.forged_session;if(!raw||!process.env.AUTH_SECRET)return json(res,200,{authenticated:false});
 const [p,s]=raw.split(".");if(!p||!s)return json(res,200,{authenticated:false});
 const expected=crypto.createHmac("sha256",process.env.AUTH_SECRET).update(p).digest("base64url");
 const A=Buffer.from(s),B=Buffer.from(expected);if(A.length!==B.length||!crypto.timingSafeEqual(A,B))return json(res,200,{authenticated:false});
 try{const d=JSON.parse(Buffer.from(p,"base64url").toString());if(Date.now()>d.exp)return json(res,200,{authenticated:false});return json(res,200,{authenticated:true,user:{email:d.email}})}catch{return json(res,200,{authenticated:false})}
};