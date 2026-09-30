const crypto=require("crypto");
const COOKIE_TTL=15*60;
function json(res,status,body){res.statusCode=status;res.setHeader("Content-Type","application/json");res.end(JSON.stringify(body))}
function token(email,exp){const payload=Buffer.from(JSON.stringify({email,exp})).toString("base64url");const sig=crypto.createHmac("sha256",process.env.AUTH_SECRET).update(payload).digest("base64url");return payload+"."+sig}
module.exports=async(req,res)=>{
 if(req.method!=="POST")return json(res,405,{error:"Method not allowed"});
 if(!process.env.AUTH_SECRET||!process.env.RESEND_API_KEY||!process.env.EMAIL_FROM)return json(res,503,{error:"Sign-in is being configured."});
 let body=req.body||{};if(typeof body==="string"){try{body=JSON.parse(body)}catch{}}
 const email=String(body.email||"").trim().toLowerCase();
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return json(res,400,{error:"Enter a valid email address."});
 const exp=Date.now()+COOKIE_TTL*1000;const t=token(email,exp);
 const origin=(process.env.PUBLIC_SITE_URL||"https://www.forgedsaga.com").replace(/\/$/,"");
 const link=origin+"/api/auth/verify?token="+encodeURIComponent(t);
 const r=await fetch("https://api.resend.com/emails",{method:"POST",headers:{"Authorization":"Bearer "+process.env.RESEND_API_KEY,"Content-Type":"application/json"},body:JSON.stringify({from:process.env.EMAIL_FROM,to:[email],subject:"Your Forged Community sign-in link",html:'<div style="font-family:Arial,sans-serif"><h2>Enter the Forged Community</h2><p>Your secure sign-in link is valid for 15 minutes.</p><p><a href="'+link+'">Sign in to the Forged Community</a></p><p>If you did not request this, you can ignore this email.</p></div>'})});
 if(!r.ok)return json(res,502,{error:"We could not send the sign-in email. Please try again."});
 return json(res,200,{ok:true,message:"Check your email for your secure sign-in link."});
};