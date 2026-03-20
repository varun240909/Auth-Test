import Joi from "joi";

export const registerSchema = Joi.object({
  name: Joi.string().min(2).max(50).required(),

  email: Joi.string().email().required(),

  password: Joi.string()
    .min(6)
    .pattern(new RegExp("^[a-zA-Z0-9@#$%^&*!]{6,30}$"))
    .required(),

  role: Joi.string().valid("user", "admin"),
});

export const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});
