import express from "express";
import { getUsers, deleteUser } from "../controllers/user.controller.js";

const router = express.Router();

router.get("/users", getUsers);
router.delete("/users/:user_id", deleteUser);

export default router;
