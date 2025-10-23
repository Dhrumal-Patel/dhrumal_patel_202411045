const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const { PrismaClient } = require('@prisma/client');

const app = express();
const prisma = new PrismaClient();
const PORT = 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret';

app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/ecom', { useNewUrlParser: true, useUnifiedTopology: true });

// Product Model (MongoDB)
const productSchema = new mongoose.Schema({
  sku: String,
  name: String,
  price: Number,
  category: String,
  updatedAt: { type: Date, default: Date.now }
});
const Product = mongoose.model('Product', productSchema);

// Middleware to verify JWT
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Auth Routes
app.post('/auth/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  const hash = await bcrypt.hash(password, 10);
  try {
    const user = await prisma.user.create({
      data: { name, email, passwordHash: hash, role: role || 'customer' }
    });
    res.json(user);
  } catch (err) {
    res.status(400).json({ message: 'User exists' });
  }
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !await bcrypt.compare(password, user.passwordHash)) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token, user });
});

// Product Routes
app.get('/products', async (req, res) => {
  const { search, category } = req.query;
  let query = {};
  if (search) query.name = { $regex: search, $options: 'i' };
  if (category) query.category = category;
  const products = await Product.find(query).sort({ price: -1 }); // Server-side sort desc
  res.json(products);
});

app.post('/products', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin only' });
  const product = new Product(req.body);
  await product.save();
  res.json(product);
});

app.put('/products/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin only' });
  const product = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(product);
});

app.delete('/products/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin only' });
  await Product.findByIdAndDelete(req.params.id);
  res.json({ message: 'Deleted' });
});

// Cart (simple in-memory, per session - not persisted)
const carts = {}; // userId -> [ { productId, quantity } ]

app.get('/cart', authenticate, (req, res) => {
  res.json(carts[req.user.id] || []);
});

app.post('/cart', authenticate, (req, res) => {
  const { productId, quantity } = req.body;
  if (!carts[req.user.id]) carts[req.user.id] = [];
  const item = carts[req.user.id].find(i => i.productId === productId);
  if (item) item.quantity += quantity;
  else carts[req.user.id].push({ productId, quantity });
  res.json(carts[req.user.id]);
});

app.delete('/cart/:productId', authenticate, (req, res) => {
  carts[req.user.id] = carts[req.user.id]?.filter(i => i.productId !== req.params.productId) || [];
  res.json(carts[req.user.id]);
});

// Checkout
app.post('/checkout', authenticate, async (req, res) => {
  const cart = carts[req.user.id] || [];
  if (!cart.length) return res.status(400).json({ message: 'Empty cart' });

  let total = 0;
  const items = [];
  for (const item of cart) {
    const product = await Product.findById(item.productId);
    if (!product) continue;
    const priceAtPurchase = product.price;
    total += priceAtPurchase * item.quantity;
    items.push({ productId: item.productId, quantity: item.quantity, priceAtPurchase });
  }

  const order = await prisma.order.create({
    data: {
      userId: req.user.id,
      total,
      items: {
        create: items
      }
    }
  });

  carts[req.user.id] = []; // Clear cart
  res.json(order);
});

app.listen(PORT, () => console.log(`Backend on port ${PORT}`));