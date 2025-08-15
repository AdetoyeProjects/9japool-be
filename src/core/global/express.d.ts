import { UserDocument } from 'src/api/user/schema/user.schema';

declare global {
    namespace Express {
        interface Request {
            user?: UserDocument;
        }
    }
}

export {};
