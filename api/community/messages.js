const {init}=require("../_lib/db");
const {session,hashEmail}=require("../_lib/auth");

const BANNED=/\b(?:nude|nudity|porn|onlyfans|escort|crypto giveaway|wire transfer|gift card|guaranteed profit)\b/i;
function out(res,status,body){res.statusCode=status;res.setHeader("Content-Type","application/json");res.end(JSON.stringify(body))}
function bodyOf(req){let body=req.body||{};if(typeof body==="string")body=JSON.parse(body);return body}
function moderators(){return new Set(String(process.env.MODERATOR_EMAILS||"").toLowerCase().split(",").map(x=>x.trim()).filter(Boolean))}

module.exports=async(req,res)=>{
  const user=session(req);if(!user)return out(res,401,{error:"Sign in required."});
  try{
    const db=await init(),sender=hashEmail(user.email),isModerator=moderators().has(String(user.email).toLowerCase());
    if(req.method==="GET"){
      if(req.query&&req.query.action==="moderation"){
        if(!isModerator)return out(res,403,{error:"Moderator access required."});
        const q=await db.query("SELECT m.id,m.body,m.created_at,p.display_name FROM forged_private_messages m JOIN forged_profiles p ON p.email_hash=m.sender_hash WHERE m.status='pending' ORDER BY m.created_at ASC LIMIT 100");
        return out(res,200,{messages:q.rows});
      }
      if(req.query&&req.query.memberId){
        const memberId=Number(req.query.memberId);if(!Number.isInteger(memberId))return out(res,400,{error:"Invalid member."});
        const recipient=await db.query("SELECT email_hash,display_name FROM forged_profiles WHERE member_id=$1",[memberId]);
        if(!recipient.rows[0])return out(res,404,{error:"Member not found."});
        const other=recipient.rows[0].email_hash;
        const block=await db.query("SELECT 1 FROM forged_blocks WHERE (blocker_hash=$1 AND blocked_hash=$2) OR (blocker_hash=$2 AND blocked_hash=$1)",[sender,other]);
        if(block.rows[0])return out(res,403,{error:"This conversation is unavailable."});
        const q=await db.query("SELECT id,sender_hash,body,status,created_at FROM forged_private_messages WHERE ((sender_hash=$1 AND recipient_hash=$2) OR (sender_hash=$2 AND recipient_hash=$1)) AND (status='approved' OR sender_hash=$1) ORDER BY created_at ASC LIMIT 100",[sender,other]);
        return out(res,200,{member:{memberId,displayName:recipient.rows[0].display_name},messages:q.rows.map(m=>({...m,isMine:m.sender_hash===sender}))});
      }
      const directory=await db.query(`SELECT p.member_id AS "memberId",p.display_name AS "displayName",p.guardian,p.realm FROM forged_profiles p WHERE p.allow_direct_messages=true AND p.email_hash<>$1 AND NOT EXISTS(SELECT 1 FROM forged_blocks b WHERE (b.blocker_hash=$1 AND b.blocked_hash=p.email_hash) OR (b.blocker_hash=p.email_hash AND b.blocked_hash=$1)) ORDER BY p.updated_at DESC LIMIT 100`,[sender]);
      return out(res,200,{members:directory.rows});
    }
    const body=bodyOf(req);
    if(req.method==="POST"&&body.action==="send"){
      const memberId=Number(body.memberId),text=String(body.body||"").trim().slice(0,1000);
      if(!Number.isInteger(memberId)||!text)return out(res,400,{error:"Choose a member and write a message."});
      if(BANNED.test(text))return out(res,400,{error:"This message violates the no-adult-content or anti-scam rules."});
      const mine=await db.query("SELECT 1 FROM forged_profiles WHERE email_hash=$1",[sender]);
      if(!mine.rows[0])return out(res,400,{error:"Create your Forged profile first."});
      const recipient=await db.query("SELECT email_hash,display_name,allow_direct_messages FROM forged_profiles WHERE member_id=$1",[memberId]);
      if(!recipient.rows[0]||!recipient.rows[0].allow_direct_messages)return out(res,404,{error:"This member is not accepting private messages."});
      const other=recipient.rows[0].email_hash;if(other===sender)return out(res,400,{error:"You cannot message yourself."});
      const block=await db.query("SELECT 1 FROM forged_blocks WHERE (blocker_hash=$1 AND blocked_hash=$2) OR (blocker_hash=$2 AND blocked_hash=$1)",[sender,other]);
      if(block.rows[0])return out(res,403,{error:"This conversation is unavailable."});
      const rate=await db.query("SELECT count(*)::int AS count FROM forged_private_messages WHERE sender_hash=$1 AND created_at>now()-interval '1 hour'",[sender]);
      if(rate.rows[0].count>=10)return out(res,429,{error:"Private-message limit reached. Try again later."});
      await db.query("INSERT INTO forged_private_messages(sender_hash,recipient_hash,body,status) VALUES($1,$2,$3,'pending')",[sender,other,text]);
      return out(res,201,{ok:true,message:"Message sent for safety review before delivery."});
    }
    if(req.method==="POST"&&body.action==="moderate"){
      if(!isModerator)return out(res,403,{error:"Moderator access required."});
      const id=Number(body.messageId),status=body.status==="approved"?"approved":"rejected";
      if(!Number.isInteger(id))return out(res,400,{error:"Invalid message."});
      await db.query("UPDATE forged_private_messages SET status=$1,moderated_at=now(),moderator_hash=$2 WHERE id=$3 AND status='pending'",[status,sender,id]);
      return out(res,200,{ok:true});
    }
    return out(res,405,{error:"Method not allowed."});
  }catch(error){return out(res,503,{error:"Private messaging is temporarily unavailable."})}
};
