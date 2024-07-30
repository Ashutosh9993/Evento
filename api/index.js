const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const UserModel = require('./models/User');
const Ticket = require('./models/Ticket');
const Event = require('./models/Event');

const app = express();
const PORT = process.env.PORT || 4000;
const MONGO_URL = process.env.MONGO_URL;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';
const BCRYPT_SALT_ROUNDS = 10;

// middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  credentials: true,
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
}));

// multer configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, file.originalname),
});
const upload = multer({ storage });

// database connection
mongoose.connect(MONGO_URL)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

const generateToken = (user) => {
  return jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '1d' });
};

const verifyToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Access denied' });

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ error: 'Invalid token' });
  }
};

// routes
app.get('/test', (req, res) => res.json({ message: 'Test OK' }));

app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
    const userDoc = await UserModel.create({ name, email, password: hashedPassword });
    res.status(201).json(userDoc);
  } catch (error) {
    res.status(422).json({ error: error.message });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await UserModel.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ error: 'Invalid password' });

    const token = generateToken(user);
    res.cookie('token', token, { httpOnly: true }).json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/profile', verifyToken, async (req, res) => {
  try {
    const user = await UserModel.findById(req.user.id).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/logout', (req, res) => {
  res.clearCookie('token').json({ message: 'Logged out successfully' });
});

app.post('/createEvent', verifyToken, upload.single('image'), async (req, res) => {
  try {
    const eventData = { ...req.body, image: req.file ? req.file.path : '', owner: req.user.id };
    const newEvent = await Event.create(eventData);
    res.status(201).json(newEvent);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/events', async (req, res) => {
  try {
    const events = await Event.find();
    res.json(events);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/event/:id', async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) return res.status(404).json({ error: 'Event not found' });
    res.json(event);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/event/:eventId/like', verifyToken, async (req, res) => {
  try {
    const event = await Event.findByIdAndUpdate(
      req.params.eventId,
      { $inc: { likes: 1 } },
      { new: true }
    );
    if (!event) return res.status(404).json({ error: 'Event not found' });
    res.json(event);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/tickets', verifyToken, async (req, res) => {
  try {
    const ticketDetails = { ...req.body, userId: req.user.id };
    const newTicket = await Ticket.create(ticketDetails);
    res.status(201).json(newTicket);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/tickets/user', verifyToken, async (req, res) => {
  try {
    const tickets = await Ticket.find({ userId: req.user.id });
    res.json(tickets);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/tickets/:id', verifyToken, async (req, res) => {
  try {
    const ticket = await Ticket.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    if (!ticket) return res.status(404).json({ error: 'Ticket not found or unauthorized' });
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// start krdo
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
