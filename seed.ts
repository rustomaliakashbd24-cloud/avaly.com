import { PrismaClient, UserRole, ProductStatus } from "@prisma/client";
import bcrypt from "bcryptjs";
const prisma=new PrismaClient();

async function main(){
  const passwordHash=await bcrypt.hash("ChangeMe123!",12);
  const admin=await prisma.user.upsert({where:{email:"admin@avaly.com"},update:{},create:{name:"AVALY Admin",email:"admin@avaly.com",passwordHash,role:UserRole.ADMIN}});
  const sellerUser=await prisma.user.upsert({where:{email:"seller@avaly.com"},update:{},create:{name:"Demo Seller",email:"seller@avaly.com",passwordHash,role:UserRole.SELLER}});
  const seller=await prisma.seller.upsert({where:{userId:sellerUser.id},update:{},create:{userId:sellerUser.id,shopName:"AVALY Demo Store",slug:"demo-store",status:"APPROVED"}});
  const cats=["Electronics","Fashion","Beauty","Home","Grocery","Shoes"];
  for(const name of cats) await prisma.category.upsert({where:{slug:name.toLowerCase()},update:{},create:{name,slug:name.toLowerCase()}});
  const electronics=await prisma.category.findUnique({where:{slug:"electronics"}});
  if(electronics) await prisma.product.upsert({where:{slug:"smartphone-pro-256gb"},update:{},create:{sellerId:seller.id,categoryId:electronics.id,name:"Smartphone Pro 256GB",slug:"smartphone-pro-256gb",description:"Demo AVALY product",price:32999,compareAt:36999,stock:50,sku:"AVL-SP-001",status:ProductStatus.ACTIVE}});
  console.log("Seed complete. Admin: admin@avaly.com / ChangeMe123!");
}
main().finally(()=>prisma.$disconnect());