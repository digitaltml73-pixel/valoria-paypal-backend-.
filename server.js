import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import multer from "multer";
import dotenv from "dotenv";
import crypto from "node:crypto";
import pg from "pg";
import { S3Client, PutObjectCommand, HeadObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { z } from "zod";

dotenv.config();
const { Pool } = pg, app = express();
const need = ["FRONTEND_ORIGIN","PAYPAL_CLIENT_ID","PAYPAL_CLIENT_SECRET","PAYPAL_WEBHOOK_ID","DATABASE_URL","S3_BUCKET","S3_ACCESS_KEY_ID","S3_SECRET_ACCESS_KEY","ADMIN_API_KEY"];
for (const k of need) if (!process.env[k]) throw new Error("Missing environment variable: " + k);

const live = (process.env.PAYPAL_ENV || "live") === "live";
const paypalBase = live ? "https://api-m.paypal.com" : "https://api-m.sandbox.paypal.com";
const origins = process.env.FRONTEND_ORIGIN.split(",").map(function(x){return x.trim();}).filter(Boolean);
const ttl = Math.min(900, Math.max(60, Number(process.env.DOWNLOAD_URL_TTL_SECONDS || 300)));
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === "production" ? {rejectUnauthorized:false} : false, max:10 });
const s3 = new S3Client({
  region: process.env.S3_REGION || "auto",
  endpoint: process.env.S3_ENDPOINT || undefined,
  forcePathStyle: process.env.S3_FORCE_PATH_STYLE === "true",
  credentials: {accessKeyId:process.env.S3_ACCESS_KEY_ID, secretAccessKey:process.env.S3_SECRET_ACCESS_KEY}
});

app.disable("x-powered-by");
app.set("trust proxy",1);
app.use(helmet());
app.use(cors({origin:function(o,cb){if(!o || origins.includes(o)) return cb(null,true); cb(new Error("Origin not allowed"));},methods:["GET","POST","OPTIONS"],allowedHeaders:["Content-Type","Authorization","Idempotency-Key","X-Admin-Key"]}));
app.use(express.json({limit:"256kb"}));
app.use("/api",rateLimit({windowMs:60000,limit:60,standardHeaders:"draft-8",legacyHeaders:false}));

const upload = multer({
  storage:multer.memoryStorage(),
  limits:{fileSize:100*1024*1024,files:1},
  fileFilter:function(_r,f,cb){return f.mimetype==="application/pdf"?cb(null,true):cb(new Error("Only PDF files are allowed"));}
});
const fail=function(res,status,msg){return res.status(status).json({error:msg});};

function admin(req,res,next){
  const a=req.header("X-Admin-Key")||"", b=process.env.ADMIN_API_KEY;
  if(a.length!==b.length || !crypto.timingSafeEqual(Buffer.from(a),Buffer.from(b))) return fail(res,401,"Unauthorized");
  next();
}
function idem(req,res,next){
  const k=req.header("Idempotency-Key")||"";
  if(k.length<16 || k.length>200) return fail(res,400,"Valid Idempotency-Key required");
  req.idempotencyKey=k; next();
}
async function token(){
  const basic=Buffer.from(process.env.PAYPAL_CLIENT_ID+":"+process.env.PAYPAL_CLIENT_SECRET).toString("base64");
  const r=await fetch(paypalBase+"/v1/oauth2/token",{method:"POST",headers:{Authorization:"Basic "+basic,"Content-Type":"application/x-www-form-urlencoded"},body:"grant_type=client_credentials"});
  if(!r.ok) throw new Error("PayPal OAuth failed");
  return (await r.json()).access_token;
}
async function paypal(path,opt){
  const t=await token();
  const r=await fetch(paypalBase+path,{...opt,headers:{"Content-Type":"application/json",Authorization:"Bearer "+t,...(opt.headers||{})}});
  const text=await r.text(); let data={}; try{data=text?JSON.parse(text):{};}catch(_){}
  if(!r.ok){const e=new Error(data.message||"PayPal API error");e.status=r.status;e.data=data;throw e;}
  return data;
}
async function verifyWebhook(req){
  const h={
    auth_algo:req.header("paypal-auth-algo"),
    cert_url:req.header("paypal-cert-url"),
    transmission_id:req.header("paypal-transmission-id"),
    transmission_sig:req.header("paypal-transmission-sig"),
    transmission_time:req.header("paypal-transmission-time")
  };
  if(Object.values(h).some(function(v){return !v;})) return false;
  const r=await paypal("/v1/notifications/verify-webhook-signature",{method:"POST",body:JSON.stringify({...h,webhook_id:process.env.PAYPAL_WEBHOOK_ID,webhook_event:req.body})});
  return r.verification_status==="SUCCESS";
}
async function paid(client,paypalOrderId,captureId){
  const q=await client.query("SELECT o.id FROM orders o WHERE o.paypal_order_id=$1 FOR UPDATE",[paypalOrderId]);
  if(!q.rows[0]) return false;
  await client.query("UPDATE orders SET status='PAID',paypal_capture_id=COALESCE($2,paypal_capture_id),paid_at=COALESCE(paid_at,NOW()),updated_at=NOW(),download_revoked=FALSE WHERE id=$1",[q.rows[0].id,captureId]);
  return true;
}

app.get("/",function(_q,res){res.json({service:"TML Digital / Valoria Market Plus PayPal Backend",status:"ok"});});
app.get("/health",async function(_q,res){try{await pool.query("SELECT 1");res.json({status:"ok",database:"ok",paypal:live?"live":"sandbox"});}catch(_){res.status(503).json({status:"degraded",database:"error"});}});

app.post("/api/admin/products",admin,async function(req,res){
  const x=z.object({externalId:z.string().min(1).max(200),name:z.string().min(1).max(200),description:z.string().max(5000).default(""),price:z.coerce.number().nonnegative(),currency:z.string().length(3).transform(function(v){return v.toUpperCase();}),pdfStorageKey:z.string().min(1).max(1024)}).parse(req.body);
  const q=await pool.query("INSERT INTO products(external_id,name,description,price,currency,pdf_storage_key) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(external_id) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,price=EXCLUDED.price,currency=EXCLUDED.currency,pdf_storage_key=EXCLUDED.pdf_storage_key,updated_at=NOW(),active=TRUE RETURNING id,external_id,name,description,price,currency,pdf_storage_key,active",[x.externalId,x.name,x.description,x.price.toFixed(2),x.currency,x.pdfStorageKey]);
  res.json(q.rows[0]);
});

app.post("/api/admin/products/:productId/pdf",admin,upload.single("file"),async function(req,res){
  if(!req.file) return fail(res,400,"PDF file is required");
  const q=await pool.query("SELECT id FROM products WHERE id=$1",[req.params.productId]);
  if(!q.rows[0]) return fail(res,404,"Product not found");
  const key="products/"+req.params.productId+"/"+crypto.randomUUID()+".pdf";
  await s3.send(new PutObjectCommand({Bucket:process.env.S3_BUCKET,Key:key,Body:req.file.buffer,ContentType:"application/pdf",ContentLength:req.file.size}));
  await pool.query("UPDATE products SET pdf_storage_key=$1,updated_at=NOW() WHERE id=$2",[key,req.params.productId]);
  res.status(201).json({storageKey:key});
});

app.get("/api/products/:externalId",async function(req,res){
  const q=await pool.query("SELECT external_id,name,description,price,currency,active FROM products WHERE external_id=$1 AND active=TRUE",[req.params.externalId]);
  if(!q.rows[0]) return fail(res,404,"Product not found");
  res.json(q.rows[0]);
});

app.post("/api/paypal/orders",idem,async function(req,res){
  const x=z.object({productId:z.string().min(1),buyerEmail:z.string().email().max(320).optional()}).parse(req.body);
  const old=await pool.query("SELECT paypal_order_id,status FROM orders WHERE idempotency_key=$1",[req.idempotencyKey]);
  if(old.rows[0]) return res.json(old.rows[0]);
  const p=await pool.query("SELECT * FROM products WHERE external_id=$1 AND active=TRUE",[x.productId]);
  if(!p.rows[0]) return fail(res,404,"Product not found");
  const product=p.rows[0];
  const local=await pool.query("INSERT INTO orders(product_id,buyer_email,amount,currency,status,idempotency_key) VALUES($1,$2,$3,$4,'PENDING',$5) RETURNING id",[product.id,x.buyerEmail||null,product.price,product.currency,req.idempotencyKey]);
  try{
    const po=await paypal("/v2/checkout/orders",{method:"POST",headers:{"PayPal-Request-Id":req.idempotencyKey},body:JSON.stringify({intent:"CAPTURE",purchase_units:[{reference_id:local.rows[0].id,custom_id:local.rows[0].id,description:product.name.slice(0,127),amount:{currency_code:product.currency,value:Number(product.price).toFixed(2)}}],application_context:{brand_name:"TML Digital",user_action:"PAY_NOW",shipping_preference:"NO_SHIPPING"}})});
    await pool.query("UPDATE orders SET paypal_order_id=$1,updated_at=NOW() WHERE id=$2",[po.id,local.rows[0].id]);
    res.status(201).json({id:po.id});
  }catch(_){await pool.query("UPDATE orders SET status='FAILED',updated_at=NOW() WHERE id=$1",[local.rows[0].id]);res.status(502).json({error:"Unable to create PayPal order"});}
});

app.post("/api/paypal/orders/:paypalOrderId/capture",async function(req,res){
  try{
    const r=await paypal("/v2/checkout/orders/"+encodeURIComponent(req.params.paypalOrderId)+"/capture",{method:"POST",headers:{"PayPal-Request-Id":crypto.randomUUID()}});
    const c=r?.purchase_units?.[0]?.payments?.captures?.[0], client=await pool.connect();
    try{await client.query("BEGIN");if(r.status==="COMPLETED" && c?.status==="COMPLETED") await paid(client,r.id,c.id);else if(c?.status==="DECLINED") await client.query("UPDATE orders SET status='FAILED',updated_at=NOW() WHERE paypal_order_id=$1 AND status<>'PAID'",[r.id]);await client.query("COMMIT");}
    catch(e){await client.query("ROLLBACK");throw e;}finally{client.release();}
    res.json({id:r.id,status:r.status,captureStatus:c?.status||null});
  }catch(e){res.status(e.status===422?409:502).json({error:"Payment capture failed"});}
});

app.get("/api/orders/:orderId/download",async function(req,res){
  const id=(req.header("Authorization")||"").replace(/^Bearer\s+/i,"");
  if(!id) return fail(res,401,"Authorization required");
  const q=await pool.query("SELECT o.status,o.download_revoked,p.pdf_storage_key FROM orders o JOIN products p ON p.id=o.product_id WHERE o.id=$1",[id]);
  const o=q.rows[0];
  if(!o || o.status!=="PAID" || o.download_revoked) return fail(res,403,"Download not available");
  try{
    await s3.send(new HeadObjectCommand({Bucket:process.env.S3_BUCKET,Key:o.pdf_storage_key}));
    const url=await getSignedUrl(s3,new GetObjectCommand({Bucket:process.env.S3_BUCKET,Key:o.pdf_storage_key,ResponseContentType:"application/pdf",ResponseContentDisposition:'attachment; filename="TML-Digital-Product.pdf"'}),{expiresIn:ttl});
    res.json({url,expiresIn:ttl});
  }catch(_){res.status(503).json({error:"Digital file is temporarily unavailable"});}
});

app.post("/api/paypal/webhook",async function(req,res){
  try{
    if(!(await verifyWebhook(req))) return fail(res,400,"Invalid webhook signature");
    const e=req.body;if(!e.id) return fail(res,400,"Missing event id");
    const ins=await pool.query("INSERT INTO webhook_events(paypal_event_id,event_type) VALUES($1,$2) ON CONFLICT(paypal_event_id) DO NOTHING RETURNING id",[e.id,e.event_type||"UNKNOWN"]);
    if(!ins.rows[0]) return res.sendStatus(200);
    const r=e.resource||{}, orderId=r.supplementary_data?.related_ids?.order_id || (e.event_type?.startsWith("CHECKOUT.ORDER.")?r.id:null);
    const client=await pool.connect();
    try{
      await client.query("BEGIN");
      switch(e.event_type){
        case "PAYMENT.CAPTURE.COMPLETED": await paid(client,orderId,r.id); break;
        case "PAYMENT.CAPTURE.DENIED": await client.query("UPDATE orders SET status='FAILED',updated_at=NOW() WHERE paypal_order_id=$1 AND status<>'PAID'",[orderId]); break;
        case "PAYMENT.CAPTURE.REFUNDED":
        case "PAYMENT.CAPTURE.REVERSED": await client.query("UPDATE orders SET status='REFUNDED',download_revoked=TRUE,updated_at=NOW() WHERE paypal_capture_id=$1",[r.id]); break;
        case "CHECKOUT.ORDER.VOIDED": await client.query("UPDATE orders SET status='CANCELLED',updated_at=NOW() WHERE paypal_order_id=$1 AND status<>'PAID'",[r.id]); break;
      }
      await client.query("COMMIT");
    }catch(e){await client.query("ROLLBACK");throw e;}finally{client.release();}
    res.sendStatus(200);
  }catch(e){console.error("Webhook error:",e.message);res.sendStatus(500);}
});

app.use(function(err,_req,res,_next){
  if(err instanceof z.ZodError) return res.status(400).json({error:"Invalid request",issues:err.issues});
  if(err instanceof multer.MulterError) return res.status(400).json({error:err.message});
  if(err?.message==="Only PDF files are allowed") return res.status(400).json({error:err.message});
  console.error(err);res.status(500).json({error:"Internal server error"});
});
app.listen(Number(process.env.PORT||3000),function(){console.log("Valoria PayPal backend listening");});
