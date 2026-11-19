import { Request, Response, NextFunction } from "express";
import { ok } from "../response";

export async function getFailedSubmissionsHandler(
  _req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    ok(res, []);
  } catch (err) {
    next(err);
  }
}

export async function retryFailedSubmissionHandler(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const { id } = req.params;
    ok(res, { id, retried: true });
  } catch (err) {
    next(err);
  }
}
