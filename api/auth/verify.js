const crypto=require("crypto");
function safeEq(a,b){const A=Buffer.from(a),B=Buffer.from(b);return A.length===B.length&&crypto.timingSafeEqual(A,B)}
module.exports=async(req,res)=>{
 const raw=String((req.query&&req.query.token)||"");const [payload,sig]=raw.split(".");
 if(!payload||!sig||!process.env.AUTH_SECRET){res.statusCode=400;return res.end("Invalid sign-in link.");}
 const expected=crypto.createHmac("sha256",process.env.AUTH_SECRET).update(payload).digest("base64url");
 if(!safeEq(sig,expected)){res.statusCode=400;return res.end("Invalid sign-in link.");}
 let data;try{data=JSON.parse(Buffer.from(payload,"base64url").toString())}catch{res.statusCode=400;return res.end("Invalid sign-in link.");}
 if(!data.email||Date.now()>data.exp){res.statusCode=400;return res.end("This sign-in link has expired.");}
 const exp=Date.now()+30*24*60*60*1000;
 const sp=Buffer.from(JSON.stringify({email:data.email,exp})).toString("base64url");
 const ss=crypto.createHmac("sha256",process.env.AUTH_SECRET).update(sp).digest("base64url");
 res.setHeader("Set-Cookie","forged_session="+sp+"."+ss+"; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000");
 res.statusCode=302;res.setHeader("Location","/#forged-community");res.end();
};