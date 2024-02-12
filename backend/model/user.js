const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "Please enter your name!"],
  },
  email: {
    type: String,
    required: [true, "Please enter your email!"],
  },
  password: {
    type: String,
    required: [true, "Please enter your password"],
    minLength: [8, "Password should be greater than 8 characters"],
    select: false,
  },
  phoneNumber: {
    type: Number,
  },
  passwordChangedAt: Date,
  addresses: [
    {
      country: {
        type: String,
      },
      city: {
        type: String,
      },
      address1: {
        type: String,
      },
      address2: {
        type: String,
      },
      zipCode: {
        type: Number,
      },
      addressType: {
        type: String,
      },
    },
  ],
  role: {
    type: String,
    default: "user",
  },
  avatar: {
    public_id: {
      type: String,
      required: true,
    },
    url: {
      type: String,
      required: true,
    },
  },
  loginAttempts: {
    type: Number,
    default: 0,
  },
  isAccountLocked: {
    type: Boolean,
    default: false,
  },
  passwordHistory: [
    {
      type: String, // Store the hashed passwords
    },
  ],
  createdAt: {
    type: Date,
    default: Date.now(),
  },
  resetPasswordToken: String,
  resetPasswordTime: Date,
});


// //  Hash password
// userSchema.pre("save", async function (next){
//   if(!this.isModified("password")){
//     next();
//   }

//   this.password = await bcrypt.hash(this.password, 10);
// });
// Inside userSchema definition
// userSchema.pre("save", async function (next) {
//   if (!this.isModified("password")) {
//     return next();
//   }

//   this.password = await bcrypt.hash(this.password, 10);
//   this.passwordChangedAt = Date.now() - 1000;
//    // Subtracting 1 second to avoid any delays
//   next();
// });

userSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    // If the password is modified, reset login attempts
    this.resetLoginAttempts();
    

    // Hash the password and set passwordChangedAt
    this.password = await bcrypt.hash(this.password, 10);

    // save curent hash value to password history
    this.updatePasswordHistory(this.password);

    this.passwordChangedAt = Date.now() - 1000; // Subtracting 1 second to avoid any delays
  }

  next();
});


// jwt token
userSchema.methods.getJwtToken = function () {
  return jwt.sign({ id: this._id}, process.env.JWT_SECRET_KEY,{
    expiresIn: process.env.JWT_EXPIRES,
  });
};
//Inside userSchema definition
userSchema.methods.isPasswordExpired = function () {
  if (this.passwordChangedAt) {
    const expirationTime = this.passwordChangedAt.getTime() + 90 * 24 * 60 * 60 * 1000; // 90 days in milliseconds
    return expirationTime < Date.now();
  }
  // If passwordChangedAt is not set, consider it as expired
  return true;
};
//compare password
userSchema.methods.comparePassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// ********************** brute force attack saftey ****************

userSchema.methods.incrementLoginAttempts = function () {
  this.loginAttempts += 1;
};

// Method to reset login attempts
userSchema.methods.resetLoginAttempts = function () {
  this.loginAttempts = 0;
};

// Method to lock the account
userSchema.methods.lockAccount = function () {
  this.isAccountLocked = true;
};

// Method to unlock the account
userSchema.methods.unlockAccount = function () {
  this.isAccountLocked = false;
};

// Example middleware to handle failed login attempts
userSchema.methods.handleFailedLogin = function () {
  this.incrementLoginAttempts();

  // Check if login attempts exceed a threshold
  if (this.loginAttempts >= 3) {
    // Lock the account
    this.lockAccount();
  }
};

// Example middleware to handle successful login
userSchema.methods.handleSuccessfulLogin = function () {
  // Reset login attempts on successful login
  this.resetLoginAttempts();
};


// password history middleware
// Method to update password history on password change
userSchema.methods.updatePasswordHistory = function (currentPasswordHash) {
  // Push the current hashed password to the history
  this.passwordHistory.push(currentPasswordHash);

  // Keep only the last N passwords in the history (e.g., 5)
  const maxHistoryLength = 5;
  if (this.passwordHistory.length > maxHistoryLength) {
    this.passwordHistory = this.passwordHistory.slice(-maxHistoryLength);
  }
};

// Method to check password history
userSchema.methods.checkPasswordHistory = function (newPassword) {
  // Check if the new password matches any of the previous passwords
  const isPasswordInHistory = this.passwordHistory.some((oldPassword) => {
    return bcrypt.compareSync(newPassword, oldPassword);
  });

  return !isPasswordInHistory;
};




module.exports = mongoose.model("User", userSchema);
