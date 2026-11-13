import type { Request, Response, NextFunction } from 'express';

export function authenticate(req: Request, res: Response, next: NextFunction): void {
  next();
}

export const hasRole = (role: string) => (req: Request, res: Response, next: NextFunction) => next();
