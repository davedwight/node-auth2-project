// The token must expire in one day, and must provide the following information
// in its payload:

// {
//   "subject"  : 1       // the user_id of the authenticated user
//   "username" : "bob"   // the username of the authenticated user
//   "role_name": "admin" // the role of the authenticated user
// }
// */

const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../secrets");

module.exports = function (user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  };
  const options = {
    expiresIn: "1d",
  };
  return jwt.sign(payload, JWT_SECRET, options);
};
