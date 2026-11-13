import { Router } from 'express';

export const adminRouter = Router();
adminRouter.post('/roles', assignRole);
