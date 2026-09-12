# AVALY Backend — Step 2

এটি AVALY frontend-এর পরের ধাপ: **real backend + PostgreSQL/Prisma API**।

## 1) PostgreSQL
Supabase/Neon-এ PostgreSQL database তৈরি করুন এবং `.env`-এ DATABASE_URL বসান।

## 2) Run
```bash
npm install
npx prisma generate
npx prisma migrate dev --name init
npm run prisma:seed
npm run dev
```

API: `http://localhost:4000`

## Main endpoints
- `GET /api/health`
- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/products`
- `GET /api/products/:slug`
- `GET /api/categories`
- `GET /api/me`
- `GET /api/me/orders`
- `POST /api/orders`
- `POST /api/products` (seller/admin)
- `POST /api/sellers/apply`
- `GET /api/admin/orders` (admin)
- `PATCH /api/orders/:id/status` (admin)

## Demo admin
Email: `admin@avaly.com`
Password: `ChangeMe123!`

Production-এর আগে password/secret অবশ্যই পরিবর্তন করবেন।
