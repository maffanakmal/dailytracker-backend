import supabaseClient from '../config/supabase.js';

// GET all jobs
export const getJobs = async (req, res) => {
  try {
    const { data, error } = await supabaseClient
      .from("jobs")
      .select("job_id, company, job_title, application_status, job_type, location, description, job_platform, progress, application_priority")
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(500).json({
        success: false,
        message: error.message
      });
    }

    res.json({
      success: true,
      data
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: err.message
    });
  }
};

// GET single job by ID
export const getJobById = async (req, res) => {
  try {
    const { job_id } = req.params;

    const { data, error } = await supabaseClient
      .from("jobs")
      .select("job_id, company, job_title, application_status, job_type, location, description, job_platform, progress, application_priority")
      .eq("job_id", job_id)
      .single();

    if (error) {
      return res.status(500).json({
        success: false,
        message: error.message
      });
    }

    res.json({
      success: true,
      data
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: err.message
    });
  }
};

export const getMyJob = async (req, res) => {
  try {
    const user_id = req.user.user_id;

    const { data, error } = await supabaseClient
      .from("jobs")
      .select(`
        job_id,
        company,
        job_title,
        application_status,
        job_type,
        location,
        description,
        job_platform,
        progress,
        application_priority
      `)
      .eq("user_id", user_id)
      .order("created_at", { ascending: false });

    if (error) {
      return res.status(500).json({
        success: false,
        message: error.message,
      });
    }

    return res.json({
      success: true,
      data,
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};


// CREATE new job
export const addJob = async (req, res) => {
  try {
    const user_id = req.user.user_id;

    const {
      company,
      job_title,
      application_status,
      job_type,
      location,
      description,
      job_platform,
      progress,
      application_priority
    } = req.body;

    const errors = {};

    if (!company?.trim()) errors.company = ["Company name is required"];
    if (!job_title?.trim()) errors.job_title = ["Job title is required"];
    if (!job_type?.trim()) errors.job_type = ["Job type is required"];
    if (!job_platform?.trim()) errors.job_platform = ["Job platform is required"];

    const STATUS = ["Applied", "Screening", "Test", "Interviewing", "Offer", "Accepted", "Rejected"];
    const PRIORITY = ["High", "Normal", "Low"];

    if (!STATUS.includes(application_status)) {
      errors.application_status = ["Invalid application status"];
    }

    if (!PRIORITY.includes(application_priority)) {
      errors.application_priority = ["Invalid priority"];
    }

    if (Object.keys(errors).length > 0) {
      return res.status(422).json({ success: false, errors });
    }

    const { data, error } = await supabaseClient
      .from("jobs")
      .insert([
        {
          user_id, // 🔥 dari session
          company: company.trim(),
          job_title: job_title.trim(),
          application_status,
          job_type,
          location: location?.trim() || null,
          description: description?.trim() || null,
          job_platform: job_platform.trim(),
          progress: progress?.trim() || null,
          application_priority
        }
      ])
      .select("*")
      .single();

    if (error) {
      return res.status(500).json({
        success: false,
        message: error.message
      });
    }

    return res.status(201).json({
      success: true,
      message: "Job added successfully",
      data
    });

  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
};


export const updateJob = async (req, res) => {
  try {
    const { job_id } = req.params;

    const {
      company,
      job_title,
      application_status,
      job_type,
      location,
      description,
      job_platform,
      progress,
      application_priority
    } = req.body;

    if (!job_id) {
      return res.status(400).json({
        success: false,
        message: "Job ID is required"
      });
    }

    const errors = {};

    if (!company?.trim()) errors.company = ["Company name is required"];
    if (!job_title?.trim()) errors.job_title = ["Job title is required"];
    if (!application_status?.trim()) errors.application_status = ["Application status is required"];
    if (!job_type?.trim()) errors.job_type = ["Job type is required"];
    if (!job_platform?.trim()) errors.job_platform = ["Job platform is required"];
    if (!application_priority?.trim()) errors.application_priority = ["Application priority is required"];

    if (Object.keys(errors).length > 0) {
      return res.status(422).json({
        success: false,
        errors
      });
    }

    // cek job exists
    const { data: existingJob, error: checkError } = await supabaseClient
      .from("jobs")
      .select("job_id")
      .eq("job_id", job_id)
      .single();

    if (checkError || !existingJob) {
      return res.status(404).json({
        success: false,
        message: "Job not found"
      });
    }

    const { data, error } = await supabaseClient
      .from("jobs")
      .update({
        company: company.trim(),
        job_title: job_title.trim(),
        application_status,
        job_type,
        location: location?.trim() || null,
        description: description?.trim() || null,
        job_platform: job_platform.trim(),
        progress: progress?.trim() || null,
        application_priority,
        updated_at: new Date()
      })
      .eq("job_id", job_id)
      .select()
      .single();

    if (error) {
      return res.status(500).json({
        success: false,
        message: error.message
      });
    }

    res.json({
      success: true,
      message: "Job updated successfully",
      data
    });

  } catch (err) {
    res.status(500).json({
      success: false,
      message: err.message
    });
  }
};

export const deleteJob = async (req, res) => {
  try {
    const { job_id } = req.params;

    if (!job_id) {
      return res.status(400).json({
        success: false,
        message: "Job ID is required"
      });
    }

    // cek job exists
    const { data: existingJob, error: checkError } = await supabaseClient
      .from("jobs")
      .select("job_id")
      .eq("job_id", job_id)
      .single();

    if (checkError || !existingJob) {
      return res.status(404).json({
        success: false,
        message: "Job not found"
      });
    }

    const { error } = await supabaseClient
      .from("jobs")
      .delete()
      .eq("job_id", job_id);

    if (error) {
      return res.status(500).json({
        success: false,
        message: error.message
      });
    }

    res.json({
      success: true,
      message: "Job deleted successfully"
    });

  } catch (err) {
    res.status(500).json({
      success: false,
      message: err.message
    });
  }
};
