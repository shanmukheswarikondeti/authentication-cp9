const express = require("express");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const path = require("path");
//for password encryption
const bcrypt = require("bcrypt");

const databasePath = path.join(__dirname, "userData.db");

const app = express();

app.use(express.json());

let database = null;

const initializeDbAndServer = async () => {
  try {
    database = await open({
      filename: databasePath,
      driver: sqlite3.Database,
    });

    app.listen(3000, () =>
      console.log("Server Running at http://localhost:3000/")
    );
  } catch (error) {
    console.log(`DB Error: ${error.message}`);
    process.exit(1);
  }
};

initializeDbAndServer();

const validatePassword = (password) => {
  return password.length > 5;
};

//API 1--->User Registration
//Scenario 1 If the username already exists
//Scenario 2 If the registrant provides a password with less than 5 characters
//Scenario 3 Successful registration of the registrant
//change the password to encrypted format using bcrypt() third party library
//npm install bcrypt --save
//const hashedPassword=await bcrypt.hash(password,saltRounds);

app.post("/register", async (request, response) => {
  const { username, name, password, gender, location } = request.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const selectUserQuery = `SELECT * FROM user 
                                 WHERE username = '${username}';`;
  const databaseUser = await database.get(selectUserQuery);

  if (databaseUser === undefined) {
    const createUserQuery = `INSERT INTO user 
                                        (username, name, password, gender, location)
                                        VALUES('${username}',
                                                '${name}',
                                                '${hashedPassword}',
                                                '${gender}',
                                                '${location}');`;
    if (validatePassword(password)) {
      await database.run(createUserQuery);
      response.send("User created successfully"); //scenario 3
    } else {
      response.status(400);
      response.send("Password is too short"); //scenario 2
    }
  } else {
    response.status(400);
    response.send("User already exists"); //scenario 1
  }
});

//API 2 User Login
//Scenario 1 If an unregistered user tries to login
//Scenario 2 If the user provides incorrect password
//Scenario 3 Successful login of the user
//compare the encrypted password and given password is same
//const result=await bcrypt.compare(givenPassword,passwordInDb);

app.post("/login", async (request, response) => {
  const { username, password } = request.body;
  const selectUserQuery = `SELECT * FROM user WHERE username = '${username}';`;
  const databaseUser = await database.get(selectUserQuery);

  if (databaseUser === undefined) {
    response.status(400);
    response.send("Invalid user"); //scenario 1
  } else {
    const isPasswordMatched = await bcrypt.compare(
      password,
      databaseUser.password
    );
    if (isPasswordMatched === true) {
      response.send("Login success!"); //scenario 3
    } else {
      response.status(400);
      response.send("Invalid password"); //scenario 2
    }
  }
});

//APT 3--->Change Password
//Scenario 1 If the user provides incorrect current password
//Scenario 2 If the user provides new password with less than 5 characters
//Scenario 3 Successful password update

app.put("/change-password", async (request, response) => {
  const { username, oldPassword, newPassword } = request.body;
  const selectUserQuery = `SELECT * FROM user 
                             WHERE username = '${username}';`;
  const databaseUser = await database.get(selectUserQuery);
  if (databaseUser === undefined) {
    response.status(400);
    response.send("Invalid user");
  } else {
    const isPasswordMatched = await bcrypt.compare(
      oldPassword,
      databaseUser.password
    );
    if (isPasswordMatched === true) {
      if (validatePassword(newPassword)) {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const updatePasswordQuery = `UPDATE user
                                        SET password = '${hashedPassword}'
                                        WHERE username = '${username}';`;
        const user = await database.run(updatePasswordQuery);
        response.send("Password updated"); //scenario 3
      } else {
        response.status(400);
        response.send("Password is too short"); //scenario 2
      }
    } else {
      response.status(400);
      response.send("Invalid current password"); //scenario 1
    }
  }
});

module.exports = app;
