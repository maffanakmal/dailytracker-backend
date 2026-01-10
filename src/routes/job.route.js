import express from 'express';
import {
    getJobs,
    getMyJob,
    getJobById,
    addJob,
    updateJob,
    deleteJob
} from '../controllers/job.controller.js';   

const router = express.Router();

router.get("/", getJobs);
router.get("/my", getMyJob);
router.get("/:job_id", getJobById);
router.post("/", addJob);
router.put("/:job_id", updateJob);
router.delete("/:job_id", deleteJob);

export default router;
