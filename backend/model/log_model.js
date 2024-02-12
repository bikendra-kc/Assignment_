const mongoose = require("mongoose");

const Log = new mongoose.Schema(
     {
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },
  message: {
    type: String,
  },
  level: {
    type: String,
  },
  timestamp: {
    type: Date,
  },
});

module.exports = mongoose.model("logModel", Log);
