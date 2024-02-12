const express = require("express");
const User = require("../model/user");
const router = express.Router();
const cloudinary = require("cloudinary");
const ErrorHandler = require("../utils/ErrorHandler");
const catchAsyncErrors = require("../middleware/catchAsyncErrors");
const jwt = require("jsonwebtoken");
const sendMail = require("../utils/sendMail");

const Log = require("../model/log_model");
const sendToken = require("../utils/jwtToken");
const { isAuthenticated, isAdmin, isPasswordExpired 
 } = require("../middleware/auth");
const passwordValidator = require('password-validator');
const schema = new passwordValidator();
schema
  .is().min(8)                                    // Minimum length 8
  .has().uppercase()                               // Must have uppercase letters
  .has().lowercase()                               // Must have lowercase letters
  .has().digits()                                  // Must have digits
  .has().symbols();                                // Must have special characters

// create user
router.post("/create-user", async (req, res, next) => {
  try {
    const { name, email, password, avatar } = req.body;
    const userEmail = await User.findOne({ email });
 
    if (userEmail) {
      return next(new ErrorHandler("User already exists", 400));
    }

    // Validate password complexity
    if (!schema.validate(password)) {
      return next(new ErrorHandler("Password must include uppercase, lowercase, digits and special character", 400));
    }
 
    const myCloud = await cloudinary.v2.uploader.upload(avatar, {
      folder: "Avatars",
    });
 
    const user = {
      name: name,
      email: email,
      password: password,
      avatar: {
        public_id: myCloud.public_id,
        url: myCloud.secure_url,
      },
    };
 
    const activationToken = createActivationToken(user);
 
    const activationUrl = `http://localhost:8000/api/v2/user/activation/${activationToken}`;
 
    try {
      await sendMail({
        email: user.email,
        subject: "Activate your account",
        message: `Hello ${user.name}, please click on the link to activate your account: ${activationUrl}`,
      });
      res.status(201).json({
        success: true,
        message: `Please check your email (${user.email}) to activate your account!`,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  } catch (error) {
    return next(new ErrorHandler(error.message, 400));
  }
});



// create activation token
const createActivationToken = (user) => {
  return jwt.sign(user, process.env.ACTIVATION_SECRET, {
    expiresIn: "5m",
  });
};

// activate user
router.get("/activation/:activation_token", async (req, res) => {
  try {
    const { activation_token } = req.params;

    // Verify the activation token
    const decodedToken = jwt.verify(
      activation_token,
      process.env.ACTIVATION_SECRET
    );

    if (!decodedToken) {
      return res.status(400).json({ error: "Invalid token" });
    }

    // Extract user information from the token
    const { name, email, password, avatar } = decodedToken;

    // Check if the user already exists in the database
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }

    // If the user doesn't exist, create a new user
    const newUser = await User.create({
      name,
      email,
      password,
      avatar,
      // Add any other necessary fields
    });

    return res
      .status(201)
      .json({ message: "User activated successfully", user: newUser });
  } catch (error) {
    console.error("Activation Error:", error);
    return res.status(500).json({ error: "Failed to activate user" });
  }
});
 

// login user
// router.post(
//   "/login-user",
//   catchAsyncErrors(async (req, res, next) => {
//     try {
//       const { email, password } = req.body;

//       if (!email || !password) {
//         return next(new ErrorHandler("Please provide the all fields!", 400));
//       }

//       const user = await User.findOne({ email }).select("+password");

//       if (!user) {
//         return next(new ErrorHandler("User doesn't exists!", 400));
//       }

//       const isPasswordValid = await user.comparePassword(password);

//       if (!isPasswordValid) {
//         return next(
//           new ErrorHandler("Please provide the correct information", 400)
//         );
//       }

//       sendToken(user, 201, res);
//     } catch (error) {
//       return next(new ErrorHandler(error.message, 500));
//     }
//   })
// );

router.post(
  "/login-user",
  catchAsyncErrors(async (req, res, next) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return next(new ErrorHandler("Please provide all fields!", 400));
      }

      const user = await User.findOne({ email }).select("+password");

      if (!user) {
        return next(new ErrorHandler("User doesn't exist!", 400));
      }

      // Check if the account is locked
      if (user.isAccountLocked) {
        return next(
          new ErrorHandler("Account is locked. Please try again later.", 401)
        );
      }

      const isPasswordValid = await user.comparePassword(password);

      if (!isPasswordValid) {
        // Handle failed login attempts and check if the account should be locked
        user.handleFailedLogin();
        await user.save(); // Save the updated user document

        return next(
          new ErrorHandler("Please provide the correct information", 400)
        );
      }

      // Reset login attempts on successful login
      user.handleSuccessfulLogin();
      await user.save(); // Save the updated user document

      sendToken(user, 201, res);

      // Create a log entry for successful login
      const logEntry = await Log.create({
        userId: user._id, // Use user ID instead of email
        message: `${user.name} has login successful`,
        level: "info",
        timestamp: new Date().toISOString(),
        // Add any other necessary fields
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// load user
router.get(
  "/getuser",
  isAuthenticated,
  // isPasswordExpired,
  catchAsyncErrors(async (req, res, next) => {
    try {
      const user = await User.findById(req.user.id);

      if (!user) {
        return next(new ErrorHandler("User doesn't exists", 400));
      }

      res.status(200).json({
        success: true,
        user,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// log out user
router.get(
  "/logout",
  catchAsyncErrors(async (req, res, next) => {
    try {
      res.cookie("token", null, {
        expires: new Date(Date.now()),
        httpOnly: true,
        sameSite: "none",
        secure: true,
      });
      res.status(201).json({
        success: true,
        message: "Log out successful!",
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// update user info
router.put(
  "/update-user-info",
  isAuthenticated,
  catchAsyncErrors(async (req, res, next) => {
    try {
      const { email, password, phoneNumber, name } = req.body;

      const user = await User.findOne({ email }).select("+password");

      if (!user) {
        return next(new ErrorHandler("User not found", 400));
      }

      const isPasswordValid = await user.comparePassword(password);

      if (!isPasswordValid) {
        return next(
          new ErrorHandler("Please provide the correct information", 400)
        );
      }

      user.name = name;
      user.email = email;
      user.phoneNumber = phoneNumber;

      await user.save();

      res.status(201).json({
        success: true,
        user,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// get all log of user
router.get(
  "/getlogs",
  isAuthenticated,
  catchAsyncErrors(async (req, res, next) => {
    try {
      const log = await Log.find({ userId: req.user._id });
   

      res.status(201).json({
        success: true,
        logs: log,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// update user avatar
router.put(
  "/update-avatar",
  isAuthenticated,
  catchAsyncErrors(async (req, res, next) => {
    try {
      let existsUser = await User.findById(req.user.id);
      if (req.body.avatar !== "") {
        const imageId = existsUser.avatar.public_id;

        await cloudinary.v2.uploader.destroy(imageId);

        const myCloud = await cloudinary.v2.uploader.upload(req.body.avatar, {
          folder: "avatars",
          width: 150,
        });

        existsUser.avatar = {
          public_id: myCloud.public_id,
          url: myCloud.secure_url,
        };
      }

      await existsUser.save();

      res.status(200).json({
        success: true,
        user: existsUser,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// update user addresses
router.put(
  "/update-user-addresses",
  isAuthenticated,
  catchAsyncErrors(async (req, res, next) => {
    try {
      const user = await User.findById(req.user.id);

      const sameTypeAddress = user.addresses.find(
        (address) => address.addressType === req.body.addressType
      );
      if (sameTypeAddress) {
        return next(
          new ErrorHandler(`${req.body.addressType} address already exists`)
        );
      }

      const existsAddress = user.addresses.find(
        (address) => address._id === req.body._id
      );

      if (existsAddress) {
        Object.assign(existsAddress, req.body);
      } else {
        // add the new address to the array
        user.addresses.push(req.body);
      }

      await user.save();

      res.status(200).json({
        success: true,
        user,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// delete user address
router.delete(
  "/delete-user-address/:id",
  isAuthenticated,
  catchAsyncErrors(async (req, res, next) => {
    try {
      const userId = req.user._id;
      const addressId = req.params.id;

      await User.updateOne(
        {
          _id: userId,
        },
        { $pull: { addresses: { _id: addressId } } }
      );

      const user = await User.findById(userId);

      res.status(200).json({ success: true, user });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// update user password
router.put(
  "/update-user-password",
  isAuthenticated,
  catchAsyncErrors(async (req, res, next) => {
    try {
      const user = await User.findById(req.user.id).select("+password");

      const isPasswordMatched = await user.comparePassword(
        req.body.oldPassword
      );

      if (!isPasswordMatched) {
        return next(new ErrorHandler("Old password is incorrect!", 400));
      }

      if (req.body.newPassword !== req.body.confirmPassword) {
        return next(new ErrorHandler("Passwords don't match!", 400));
      }

      // Check if the new password is in the password history
      const isPasswordHistoryValid = user.checkPasswordHistory(
        req.body.newPassword
      );

      if (!isPasswordHistoryValid) {
        return next(new ErrorHandler("Cannot use same previous password.", 400));
      }
      // Update the user's password and update the password history
      user.password = req.body.newPassword;
    

      await user.save();

      res.status(200).json({
        success: true,
        message: "Password updated successfully!",
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 400)); // Adjust the status code as needed
    }
  })
);


// find user infoormation with the userId
router.get(
  "/user-info/:id",

  catchAsyncErrors(async (req, res, next) => {
    try {
      const user = await User.findById(req.params.id);

      res.status(201).json({
        success: true,
        user,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// all users --- for admin
router.get(
  "/admin-all-users",
  isAuthenticated,
  isAdmin("Admin"),
  catchAsyncErrors(async (req, res, next) => {
    try {
      const users = await User.find().sort({
        createdAt: -1,
      });
      res.status(201).json({
        success: true,
        users,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// delete users --- admin
router.delete(
  "/delete-user/:id",
  isAuthenticated,
  isAdmin("Admin"),
  catchAsyncErrors(async (req, res, next) => {
    try {
      const user = await User.findById(req.params.id);

      if (!user) {
        return next(
          new ErrorHandler("User is not available with this id", 400)
        );
      }

      const imageId = user.avatar.public_id;

      await cloudinary.v2.uploader.destroy(imageId);

      await User.findByIdAndDelete(req.params.id);

      res.status(201).json({
        success: true,
        message: "User deleted successfully!",
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

module.exports = router;
