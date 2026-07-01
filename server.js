const cookieParser = require("cookie-parser");
const cors = require('cors');
const express = require ('express');

//const path = require('path');

const mysql = require('mysql2');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors({
  origin: "http://localhost:3000",
  credentials: true
}));
app.use(cookieParser());
//app.use(cors());

//app.use(express.static(path.join(__dirname, 'myproject/dist')));

const SECRET_KEY = 'mysecretkey';


const db = mysql.createConnection({
    host: 'localhost',                                      //host will be the public IPv4 address of the AWS Instance 
    user:   'root',                                         //FOR LOCALMACHINE = root         //for AWS db = root
    password: 'root@123',                                       //FOR LOCALMACHINE = root@123      //for AWS db = root
    database: 'meetup_db'
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to database:', err);
    }
    else {
        console.log('Connected to database');
    }
});

//////////////////////////////////////////////////////
//JWT AUTH MIDDLEWARE
function authenticateToken(req, res, next) {
  const token = req.cookies.token;   // read token from cookie

  if (!token) {
    return res.status(401).json({
      message: "Token required"
    });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({
        message: "Invalid token"
      });
    }

    req.user = user;
    next();
  });
}

//////////////////////////////////////////////////////
//USER SIGNUP = POST

app.post('/api/signup', (req, res) => {

  const { full_name, email, pwd_hash , ph_number} = req.body;

  if (!full_name || !email || !pwd_hash|| !ph_number ) {
    return res.status(400).json({
      message: "All fields required"
    });
  }

  const checkSql = "SELECT * FROM users WHERE email=?";

  db.query(checkSql, [email], (err, result) => {

    if (err) {
      return res.status(500).json({
        error: err.message
      });
    }

    if (result.length > 0) {
      return res.status(400).json({
        message: "Email already exists"
      });
    }

    const insertSql =
      "INSERT INTO users (full_name, email, pwd_hash, ph_number) VALUES (?, ?, ?, ?)";

    db.execute(
      insertSql,
      [full_name, email, pwd_hash, ph_number],
      (err, result) => {

        if (err) {
          return res.status(500).json({
            error: err.message
          });
        }

        res.json({
          message: "Signup successful",
          userId: result.insertId
        });
      }
    );
  });
});



//////////////////////////////////////////////////////
// 2) USER LOGIN =  POST

app.post('/api/login', (req, res) => {

  const { email, pwd_hash } = req.body;

  if (!email || !pwd_hash) {
    return res.status(400).json({
      message: "Email and pwd_hash required"
    });
  }

  const sql = "SELECT * FROM users WHERE email=?";

  db.query(sql, [email], (err, result) => {

    if (err) {
      return res.status(500).json({
        error: err.message
      });
    }

    if (result.length === 0) {
      return res.status(401).json({
        message: "User not found"
      });
    }

    const user = result[0];

    if (user.pwd_hash !== pwd_hash) {
      return res.status(401).json({
        message: "Invalid credentials"
      });
    }

    // CREATE JWT TOKEN
    const token = jwt.sign(
      {
        id: user.user_id,
        email: user.email
      },
      SECRET_KEY,
      {
        expiresIn: '1h'
      }
    );

    res.cookie("token", token, {
      httpOnly: true,
      //secure: false,
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000
    });

    return res.json({message: "Login successful"
      //token: token
      });
  });
});

///////////////////////////////////////////////////
//api/check-auth => checks the validity of token/cookie

app.get("/api/check-auth", (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ message: "Not logged in" });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);                  //=> this is where the verification is done
    return res.json({ message: "Authenticated", user: decoded });
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
});


//////////////////////////////////////////////////////
// 3) CREATE MEETUP = POST
app.post('/api/create-meetup', authenticateToken, (req, res) => {

  const {
    title,
    description,
    location,
    meetup_start_date,
    meetup_end_date,
    meetup_type,
    price,
    category,
    max_members
  } = req.body;

  const created_by = req.user.id;

  const sql = `
  INSERT INTO meetups
  (
    created_by,
    title,
    description,
    location,
    meetup_start_date,
    meetup_end_date,
    meetup_type,
    price,
    category,
    max_members
  )
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`;

  db.execute(
    sql,
    [
      created_by,
      title,
      description,
      location,
      meetup_start_date,
      meetup_end_date,
      meetup_type,
      price,
      category,
      max_members
    ],
    (err, result) => {

      if (err) {
        return res.status(500).json({
          error: err.message
        });
      }

      res.json({
        message: "Meetup created successfully",
        meetup_id: result.insertId
      });
    }
  );
});
///////////to see the list of meetups a user has subscribed to
app.get("/api/my-subscriptions", authenticateToken, (req, res) => {
  const user_id = req.user.id;

  const sql = `
    SELECT 
      m.meetup_id,
      m.title,
      m.description,
      m.location,
      m.meetup_start_date,
      m.meetup_end_date,
      m.meetup_type,
      m.price,
      m.category,
      m.max_members
    FROM meetup_subscriptions ms
    JOIN meetups m
    ON ms.meetup_id = m.meetup_id
    WHERE ms.user_id = ?
    ORDER BY ms.subscription_id DESC
  `;

  db.query(sql, [user_id], (err, result) => {
    if (err) {
      return res.status(500).json({
        error: err.message
      });
    }

    res.json(result);
  });
});

//////////////////////////////////////////////////////
// 4) SUBSCRIBE TO MEETUP (FREE) = POST

app.post('/api/subscribe-meetup', authenticateToken, (req, res) => {

  const { meetup_id } = req.body;

  const user_id = req.user.id;

  if (!meetup_id) {
    return res.status(400).json({
      message: "Meetup ID required"
    });
  }

  // CHECK IF ALREADY SUBSCRIBED
  const checkSql = `
    SELECT * FROM meetup_subscriptions
    WHERE meetup_id=? AND user_id=?
  `;

  db.query(checkSql, [meetup_id, user_id], (err, result) => {

    if (err) {
      return res.status(500).json({
        error: err.message
      });
    }

    if (result.length > 0) {
      return res.status(400).json({
        message: "Already subscribed"
      });
    }

    const insertSql = `
      INSERT INTO meetup_subscriptions
      (meetup_id, user_id)
      VALUES (?, ?)
    `;

    db.execute(
      insertSql,
      [meetup_id, user_id],
      (err, result) => {

        if (err) {
          return res.status(500).json({
            error: err.message
          });
        }

        res.json({
          message: "Subscribed successfully"
        });
      }
    );
  });
});


//////////////////////////////////////////////////////
// 5) SHOW LIST OF SUBSCRIBERS OF A MEETUP = GET

app.get('/api/meetup-subscribers/:meetup_id', authenticateToken, (req, res) => {

  const meetup_id = req.params.meetup_id;

  const sql = `
    SELECT users.user_id, users.full_name, users.email, users.ph_number
    FROM meetup_subscriptions
    JOIN users
    ON meetup_subscriptions.user_id = users.user_id
    WHERE meetup_subscriptions.meetup_id = ?
  `;

  db.query(sql, [meetup_id], (err, result) => {

    if (err) {
      return res.status(500).json({
        error: err.message
      });
    }

    res.json(result);
  });
});

/////////////////////////////////////trial////////////
app.get('/api/meetups', authenticateToken, (req, res) => {
  const sql = "SELECT * FROM meetups ORDER BY meetup_id DESC";

  db.query(sql, (err, result) => {
    if (err) {
      return res.status(500).json({
        error: err.message
      });
    }

    res.json(result);
  });
});
//////////////////////////////////////////////////////
// PROFILE = GET
app.get('/api/profile', authenticateToken, (req, res) => {
  const user_id = req.user.id;
  const sql = "SELECT user_id, full_name, email, ph_number, role FROM users WHERE user_id=?";
  db.query(sql, [user_id], (err, result) => {
    if (err) {
      return res.status(500).json({
        error: err.message
      });
    }
    if (result.length === 0) {
      return res.status(404).json({
        message: "User not found"
      });
    }
    res.json({
      user: result[0]
    });
  });
});

//////////////////////////////
//api-logout

app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ message: "Logged out" });
});


/////////////trial react route
/*app.get('/', (req, res) => {
  res.sendFile(
    path.join(__dirname, 'myproject/dist/index.html')
  );
});*/

app.get("/", (req, res) => {

    res.send("(edited part 3 trial) backend is running");

});

//////////////////////////////////////////////////////
// START SERVER

app.listen(8000, () => {
  console.log("Server running on port 8000");
});
