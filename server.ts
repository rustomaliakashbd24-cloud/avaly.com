import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { PrismaClient, Prisma, UserRole } from "@prisma/client";
import { z } from "zod";

const prisma = new PrismaClient();
const app = express();
app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL?.split(",") ?? true }));
app.use(express.json());

const secret = process.env.JWT_SECRET || "dev-secret";
type AuthReq = express.Request & { user?: { id: string; role: UserRole } };

function auth(roles?: UserRole[]) {
  return async (req: AuthReq, res: express.Response, next: express.NextFunction) => {
    try {
      const token = req.headers.authorization?.replace("Bearer ", "");
      if (!token) return res.status(401).json({ message: "Authentication required" });
      const payload = jwt.verify(token, secret) as { id: string; role: UserRole };
      if (roles && !roles.includes(payload.role)) return res.status(403).json({ message: "Forbidden" });
      req.user = payload; next();
    } catch { res.status(401).json({ message: "Invalid token" }); }
  };
}

app.get("/api/health", (_req,res)=>res.json({ok:true,service:"AVALY API"}));

app.post("/api/auth/register", async (req,res)=>{
  const body=z.object({name:z.string().min(2),email:z.string().email().optional(),phone:z.string().min(8).optional(),password:z.string().min(6)}).parse(req.body);
  const passwordHash=await bcrypt.hash(body.password,12);
  try {
    const user=await prisma.user.create({data:{name:body.name,email:body.email,phone:body.phone,passwordHash}});
    const token=jwt.sign({id:user.id,role:user.role},secret,{expiresIn:"7d"});
    res.status(201).json({token,user:{id:user.id,name:user.name,email:user.email,phone:user.phone,role:user.role}});
  } catch { res.status(409).json({message:"Email or phone already exists"}); }
});

app.post("/api/auth/login", async (req,res)=>{
  const body=z.object({identifier:z.string(),password:z.string()}).parse(req.body);
  const user=await prisma.user.findFirst({where:{OR:[{email:body.identifier},{phone:body.identifier}]}});
  if(!user || !(await bcrypt.compare(body.password,user.passwordHash))) return res.status(401).json({message:"Invalid credentials"});
  const token=jwt.sign({id:user.id,role:user.role},secret,{expiresIn:"7d"});
  res.json({token,user:{id:user.id,name:user.name,email:user.email,phone:user.phone,role:user.role}});
});

app.get("/api/products", async (req,res)=>{
  const q=String(req.query.q||""); const category=String(req.query.category||"");
  const products=await prisma.product.findMany({
    where:{status:"ACTIVE", ...(q?{OR:[{name:{contains:q,mode:"insensitive"}},{description:{contains:q,mode:"insensitive"}}]}:{}), ...(category?{category:{slug:category}}:{})},
    include:{images:true,category:{select:{name:true,slug:true}},seller:{select:{shopName:true,slug:true}}},
    orderBy:{createdAt:"desc"}
  });
  res.json(products);
});

app.get("/api/products/:slug", async(req,res)=>{
  const p=await prisma.product.findUnique({where:{slug:req.params.slug},include:{images:true,category:true,seller:{select:{shopName:true,slug:true}},reviews:{include:{user:{select:{name:true}}},orderBy:{createdAt:"desc"}}}});
  if(!p)return res.status(404).json({message:"Product not found"}); res.json(p);
});

app.post("/api/products",auth([UserRole.SELLER,UserRole.ADMIN]),async(req:AuthReq,res)=>{
  const body=z.object({categoryId:z.string(),name:z.string().min(2),slug:z.string().min(2),description:z.string(),price:z.coerce.number().nonnegative(),compareAt:z.coerce.number().nonnegative().optional(),stock:z.coerce.number().int().nonnegative(),sku:z.string(),images:z.array(z.string()).default([])}).parse(req.body);
  let sellerId:string;
  if(req.user!.role===UserRole.SELLER){const s=await prisma.seller.findUnique({where:{userId:req.user!.id}});if(!s)return res.status(400).json({message:"Seller profile missing"});sellerId=s.id}else{sellerId=String(req.body.sellerId)}
  const p=await prisma.product.create({data:{categoryId:body.categoryId,name:body.name,slug:body.slug,description:body.description,sellerId,price:new Prisma.Decimal(body.price),compareAt:body.compareAt!==undefined?new Prisma.Decimal(body.compareAt):undefined,stock:body.stock,sku:body.sku,status:"ACTIVE",images:{create:body.images.map((url,i)=>({url,sortOrder:i}))}}});
  res.status(201).json(p);
});

app.get("/api/categories",async(_req,res)=>res.json(await prisma.category.findMany({include:{children:true},where:{parentId:null}})));

app.get("/api/me",auth(),async(req:AuthReq,res)=>res.json(await prisma.user.findUnique({where:{id:req.user!.id},include:{seller:true,addresses:true}})));

app.get("/api/me/orders",auth(),async(req:AuthReq,res)=>res.json(await prisma.order.findMany({where:{userId:req.user!.id},include:{items:true,shipment:true,payment:true},orderBy:{createdAt:"desc"}})));

app.post("/api/orders",auth(),async(req:AuthReq,res)=>{
  const body=z.object({items:z.array(z.object({productId:z.string(),quantity:z.coerce.number().int().positive()})).min(1),paymentMethod:z.enum(["COD","BKASH","NAGAD","CARD"]),recipient:z.string().min(2),phone:z.string().min(8),address:z.string().min(5),district:z.string().min(2)}).parse(req.body);
  const ids=body.items.map(x=>x.productId);
  const products=await prisma.product.findMany({where:{id:{in:ids},status:"ACTIVE"}});
  if(products.length!==ids.length)return res.status(400).json({message:"One or more products unavailable"});
  const map=new Map(products.map(p=>[p.id,p]));
  let subtotal=new Prisma.Decimal(0);
  const lines=body.items.map(x=>{const p=map.get(x.productId)!; if(p.stock<x.quantity) throw new Error(`Insufficient stock: ${p.name}`); const total=p.price.mul(x.quantity); subtotal=subtotal.add(total); return {productId:p.id,sellerId:p.sellerId,name:p.name,unitPrice:p.price,quantity:x.quantity,total};});
  const delivery=new Prisma.Decimal(60); const total=subtotal.add(delivery);
  const order=await prisma.$transaction(async tx=>{
    for(const x of body.items) await tx.product.update({where:{id:x.productId},data:{stock:{decrement:x.quantity}}});
    const o=await tx.order.create({data:{orderNumber:"AVL-"+Date.now().toString().slice(-10),userId:req.user!.id,paymentMethod:body.paymentMethod,subtotal,deliveryFee:delivery,total,recipient:body.recipient,phone:body.phone,address:body.address,district:body.district,items:{create:lines},payment:{create:{method:body.paymentMethod,amount:total}},shipment:{create:{status:"PENDING"}}},include:{items:true,payment:true,shipment:true}});
    return o;
  });
  res.status(201).json(order);
});

app.patch("/api/orders/:id/status",auth([UserRole.ADMIN]),async(req,res)=>{
  const body=z.object({status:z.enum(["PENDING","CONFIRMED","PROCESSING","SHIPPED","DELIVERED","CANCELLED","RETURNED"])}).parse(req.body);
  res.json(await prisma.order.update({where:{id:req.params.id},data:{status:body.status}}));
});

app.get("/api/admin/orders",auth([UserRole.ADMIN]),async(_req,res)=>res.json(await prisma.order.findMany({include:{user:{select:{name:true,email:true,phone:true}},items:true,payment:true,shipment:true},orderBy:{createdAt:"desc"}})));

app.post("/api/sellers/apply",auth(),async(req:AuthReq,res)=>{
  const body=z.object({shopName:z.string().min(2),slug:z.string().min(2)}).parse(req.body);
  const seller=await prisma.seller.create({data:{userId:req.user!.id,shopName:body.shopName,slug:body.slug}});
  await prisma.user.update({where:{id:req.user!.id},data:{role:"SELLER"}});
  res.status(201).json(seller);
});

app.use((err:any,_req:any,res:any,_next:any)=>{console.error(err);res.status(400).json({message:err?.message||"Request failed"})});
app.listen(Number(process.env.PORT||4000),()=>console.log(`AVALY API running on ${process.env.PORT||4000}`));