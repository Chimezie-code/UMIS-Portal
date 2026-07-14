const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'umis_portal_jwt_secret_2026_secure';
const MONGO_URI = 'mongodb://127.0.0.1:27017/umis_portal';

// ─── Middleware ──────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static('.'));  // serve HTML files from same directory

// ─── MongoDB Connection ──────────────────────────────────────────────────────
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅  MongoDB connected → umis_portal database'))
  .catch(err => console.error('❌  MongoDB connection error:', err.message));

// ─── Schemas & Models ────────────────────────────────────────────────────────

const studentSchema = new mongoose.Schema({
  studentId:   { type: String, unique: true },
  firstName:   { type: String, required: true, trim: true },
  lastName:    { type: String, required: true, trim: true },
  email:       { type: String, required: true, unique: true, lowercase: true, trim: true },
  password:    { type: String, required: true },
  phone:       { type: String, required: true },
  dateOfBirth: { type: String },
  gender:      { type: String },
  nationality: { type: String },
  address:     { type: String },
  faculty:     { type: String, required: true },
  department:  { type: String, required: true },
  level:       { type: String, required: true },
  yearOfEntry: { type: String },
  programme:   { type: String, default: 'Full-Time' },
  role:        { type: String, default: 'student' },
  createdAt:   { type: Date, default: Date.now }
});

const lecturerSchema = new mongoose.Schema({
  staffId:        { type: String, unique: true },
  firstName:      { type: String, required: true, trim: true },
  lastName:       { type: String, required: true, trim: true },
  title:          { type: String, required: true },
  email:          { type: String, required: true, unique: true, lowercase: true, trim: true },
  password:       { type: String, required: true },
  phone:          { type: String, required: true },
  gender:         { type: String },
  officeLocation: { type: String },
  faculty:        { type: String, required: true },
  department:     { type: String, required: true },
  rank:           { type: String, required: true },
  specialisation: { type: String },
  courses:        { type: [String], default: [] },
  bio:            { type: String },
  role:           { type: String, default: 'lecturer' },
  createdAt:      { type: Date, default: Date.now }
});

// Hash password before saving
studentSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});
lecturerSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

const Student  = mongoose.model('Student',  studentSchema);
const Lecturer = mongoose.model('Lecturer', lecturerSchema);

// ─── Helper: generate IDs ────────────────────────────────────────────────────
async function generateStudentId(yearOfEntry, department) {
  const year = yearOfEntry || new Date().getFullYear();
  const prefix = department
    ? department.replace(/\s+/g, '').substring(0, 3).toUpperCase()
    : 'CSC';
  const count = await Student.countDocuments() + 1;
  return `${prefix}/${String(count).padStart(3, '0')}/${year}`;
}

async function generateStaffId() {
  const count = await Lecturer.countDocuments() + 1;
  return `STAFF/${String(count).padStart(4, '0')}`;
}

// ─── AUTH MIDDLEWARE ─────────────────────────────────────────────────────────
function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No token provided. Please log in.' });
  }
  try {
    req.user = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'Invalid or expired token. Please log in again.' });
  }
}

// ─── ROUTES: Student Registration ────────────────────────────────────────────
app.post('/api/students', async (req, res) => {
  try {
    const data = req.body;

    // Check duplicate email
    const exists = await Student.findOne({ email: data.email.toLowerCase() });
    if (exists) {
      return res.status(409).json({ message: 'An account with this email already exists.' });
    }

    const studentId = await generateStudentId(data.yearOfEntry, data.department);
    const student = new Student({ ...data, studentId });
    await student.save();

    res.status(201).json({
      message: 'Student registered successfully.',
      student: { studentId, firstName: student.firstName, lastName: student.lastName, email: student.email }
    });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ message: 'Email already registered.' });
    }
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

// ─── ROUTES: Lecturer Registration ───────────────────────────────────────────
app.post('/api/lecturers', async (req, res) => {
  try {
    const data = req.body;

    const exists = await Lecturer.findOne({ email: data.email.toLowerCase() });
    if (exists) {
      return res.status(409).json({ message: 'An account with this email already exists.' });
    }

    const staffId = await generateStaffId();
    const lecturer = new Lecturer({ ...data, staffId });
    await lecturer.save();

    res.status(201).json({
      message: 'Lecturer registered successfully.',
      lecturer: { staffId, firstName: lecturer.firstName, lastName: lecturer.lastName, email: lecturer.email }
    });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ message: 'Email already registered.' });
    }
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

// ─── ROUTES: Login (students + lecturers) ────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, role } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }

    let user = null;
    let userRole = role;

    if (role === 'student' || !role) {
      user = await Student.findOne({ email: email.toLowerCase() });
      if (user) userRole = 'student';
    }
    if (!user && (role === 'lecturer' || !role)) {
      user = await Lecturer.findOne({ email: email.toLowerCase() });
      if (user) userRole = 'lecturer';
    }

    if (!user) {
      return res.status(401).json({ message: 'No account found with this email address.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Incorrect password. Please try again.' });
    }

    const payload = {
      id:        user._id,
      email:     user.email,
      role:      userRole,
      firstName: user.firstName,
      lastName:  user.lastName,
      userId:    userRole === 'student' ? user.studentId : user.staffId,
      department: user.department,
      faculty:   user.faculty,
      level:     userRole === 'student' ? user.level : null,
      rank:      userRole === 'lecturer' ? user.rank : null,
      title:     userRole === 'lecturer' ? user.title : null,
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

    res.json({
      message: 'Login successful.',
      token,
      user: payload
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

// ─── ROUTES: Protected — get current user profile ────────────────────────────
app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const Model = req.user.role === 'student' ? Student : Lecturer;
    const user  = await Model.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found.' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// ─── ROUTES: Protected — list students (admin/lecturer) ──────────────────────
app.get('/api/students', verifyToken, async (req, res) => {
  const students = await Student.find().select('-password');
  res.json(students);
});

app.get('/api/lecturers', verifyToken, async (req, res) => {
  const lecturers = await Lecturer.find().select('-password');
  res.json(lecturers);
});

// ─── START SERVER ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀  UMIS Backend running at http://localhost:${PORT}`);
  console.log(`📦  Database: ${MONGO_URI}`);
  console.log(`\nEndpoints:`);
  console.log(`  POST /api/students        → Register student`);
  console.log(`  POST /api/lecturers       → Register lecturer`);
  console.log(`  POST /api/auth/login      → Login (student or lecturer)`);
  console.log(`  GET  /api/auth/me         → Get profile (auth required)\n`);
});