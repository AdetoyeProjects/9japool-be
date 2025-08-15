import * as Joi from 'joi';

export const envSchema = Joi.object({
   PORT: Joi.string().required(),
   JWT_SECRET: Joi.string().required(),
   MAILER_USER: Joi.string().required(),
   MAILER_PASS: Joi.string().required(),
   DATABASE_URL: Joi.string().required(),
   FRONTEND_URL: Joi.string().required(),
   CLOUDINARY_CLOUD_NAME: Joi.string().required(),
   CLOUDINARY_API_SECRET: Joi.string().required(),
   CLOUDINARY_API_KEY: Joi.string().required(),
});
