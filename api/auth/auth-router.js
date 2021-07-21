const bcrypt = require("bcryptjs");
const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const User = require("../users/users-model");
const tokenBuilder = require("./token-builder");

router.post("/register", validateRoleName, async (req, res, next) => {
  let user = req.body;

  const hash = bcrypt.hashSync(user.password, 8);

  user.password = hash;
  user.role_name = req.role_name;

  try {
    const newUser = await User.add(user);
    res.status(201).json(newUser);
  } catch (err) {
    next(err);
  }

  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  const { password } = req.body;
  const { user } = req;

  if (user && bcrypt.compareSync(password, user.password)) {
    const token = tokenBuilder(user);
    res.status(200).json({
      message: `${user.username} is back!`,
      token,
    });
  } else {
    next({
      status: 401,
      message: "Invalid credentials",
    });
  }
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

module.exports = router;
