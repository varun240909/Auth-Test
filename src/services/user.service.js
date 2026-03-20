import User from "../models/User.model.js";
import ApiError from "../utils/ApiError.js";

export const createUser = async (data) => {
  const existing = await User.findOne({ email: data.email });

  if (existing) {
    throw new ApiError(400, "Email already in use");
  }

  const user = await User.create(data);
  return user;
};

export const loginUser = async ({ email, password }) => {
  const user = await User.findOne({ email }).select("+password");

  if (!user) {
    throw new ApiError(401, "Invalid credentials");
  }

  const isMatch = await user.comparePassword(password);

  if (!isMatch) {
    throw new ApiError(401, "Invalid credentials");
  }

  return user;
};
