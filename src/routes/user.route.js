import express from 'express';
import {
  getUsers,
  addUser,
  getUserById,
  updateUser,
  deleteUser
} from '../controllers/user.controller.js';

const router = express.Router();

router.get("/", getUsers);
router.post("/", addUser);
router.get("/:user_id", getUserById);
router.put("/:user_id", updateUser);
router.delete("/:user_id", deleteUser);

export default router;
