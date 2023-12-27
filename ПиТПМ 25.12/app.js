var express = require("express");
var bodyParser = require("body-parser");
var sqlite3 = require("sqlite3").verbose();

var app = express();
var jsonParser = bodyParser.json();
let db = new sqlite3.Database("./db.sqlite", (err) => {
  if (err) {
    console.error(err.message);
  }
  console.log("Connected to the SQLite database.");
});

app.use(express.static(__dirname + "/public"));

db.run(
  `CREATE TABLE IF NOT EXISTS Products(
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   name TEXT,
   price REAL)`,
  (err) => {
    if (err) {
      console.error(err.message);
    }
    console.log("Created Products table.");
  },
);

app.get("/api/products", function (req, res) {
  db.all(`SELECT * FROM Products`, [], (err, rows) => {
    if (err) {
      throw err;
    }
    res.send(rows);
  });
});

app.get("/api/products/:id", function (req, res) {
  var id = req.params.id;
  var sql = "SELECT * FROM Products WHERE id = ?";
  db.get(sql, [id], (err, row) => {
    if (err) {
      throw err;
    }
    if (row) {
      res.send(row);
    } else {
      res.status(404).send();
    }
  });
});

app.post("/api/products", jsonParser, IsAdmin, function (req, res) {
  if (!req.body) return res.sendStatus(400);

  var productName = req.body.name;
  var productPrice = req.body.price;

  db.run(`INSERT INTO Products(name, price) VALUES(?, ?)`, [productName, productPrice], function (err) {
    if (err) {
      return console.error(err.message);
    }
    res.send({ id: this.lastID, name: productName, price: productPrice });
  });
});

function checkRole(req, res, next) {
  if (req.user_type_id !== 1) return res.sendStatus(403);
  next();
}

function IsAdmin(req, res, next) {
  if (req.user && req.user_type_id === 1) {
    next();
  } else {
    res.status(403).send("you not admin");
  }
}

app.delete("/api/products/:id", function (req, res) {
  var id = req.params.id;
  var sql = "DELETE FROM Products WHERE id = ?";
  db.run(sql, id, function (err) {
    if (err) {
      return console.error(err.message);
    }
    res.send({ id: id });
  });
});

app.put("/api/products/:id", jsonParser, function (req, res) {
  if (!req.body) return res.sendStatus(400);

  var id = req.params.id;
  var productName = req.body.name;
  var productPrice = req.body.price;

  var sql = "UPDATE Products SET name = ?, price = ? WHERE id = ?";
  db.run(sql, [productName, productPrice, id], function (err) {
    if (err) {
      return console.error(err.message);
    }
    res.send({ id: id, name: productName, price: productPrice });
  });
});

db.run(
  `CREATE TABLE IF NOT EXISTS Users(
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     username TEXT,
     email TEXT,
     password TEXT,
     user_type_id INTEGER)`,
  (err) => {
    if (err) {
      console.error(err.message);
    }
    console.log("Created Users table.");
  },
);

var bcrypt = require("bcrypt");
var jwt = require("jsonwebtoken");

app.post("/register", jsonParser, function (req, res) {
  if (!req.body) return res.sendStatus(400);

  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;
  var user_type_id = req.body.user_type_id;

  bcrypt.genSalt(10, function (err, salt) {
    bcrypt.hash(password, salt, function (err, hash) {
      var user = { username: username, email: email, password: hash, user_type_id: user_type_id };

      db.run(`INSERT INTO Users(username, email, password, user_type_id) VALUES(?, ?, ?, ?)`, [username, email, hash, user_type_id], function (err) {
        if (err) {
          return console.error(err.message);
        }

        var token = jwt.sign({ id: this.lastID }, "your_jwt_secret", { expiresIn: "1h" });

        res.send({ id: this.lastID, username: username, email: email, token: token });
      });
    });
  });
});

app.post("/login", jsonParser, function (req, res) {
  if (!req.body) return res.sendStatus(400);

  var email = req.body.email;
  var password = req.body.password;

  var sql = "SELECT * FROM Users WHERE email = ?";
  db.get(sql, [email], function (err, user) {
    if (err) {
      return console.error(err.message);
    }

    if (user && bcrypt.compareSync(password, user.password)) {
      var token = jwt.sign({ id: user.id, user_type_id: user.user_type_id }, "your_jwt_secret", { expiresIn: "1h" });
      res.setHeader("Authorization", "" + token);
      res.send({ id: user.id, username: user.username, email: user.email, user_type_id: user.user_type_id, token: token });
    } else {
      res.status(401).send();
    }
  });
});

app.listen(3000, function () {
  console.log("Server is listening...");
});

process.on("exit", () => {
  db.close((err) => {
    if (err) {
      console.error(err.message);
    }
    console.log("Close the database connection.");
  });
});
