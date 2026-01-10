import bcrypt from 'bcrypt';
import validator from 'validator';
import supabaseClient from '../config/supabase.js';

export const getUsers = async (req, res) => {
  try {
const { data, error } = await supabaseClient
  .from("users")
  .select(`
    user_id,
    full_name,
    email,
    role,
    created_at,
    user_sessions (
      is_active,
      expires_at,
      last_seen
    )
  `)
  .order("created_at", { ascending: false });


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

// GET single user by ID
export const getUserById = async (req, res) => {
  try {
    const { user_id } = req.params;

    const { data, error } = await supabaseClient
      .from("users")
      .select("user_id, full_name, email, created_at")
      .eq("user_id", user_id)
      .single();

    if (error) {
      if (error.code === 'PGRST116') {
        return res.status(404).json({
          success: false,
          message: "User not found"
        });
      }
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

// CREATE new user
export const addUser = async (req, res) => {
  try {
    const { full_name, email, password } = req.body;
    const errors = {};

    // Validation
    if (!full_name?.trim()) {
      errors.full_name = ["Full name is required"];
    }

    if (!email) {
      errors.email = ["Email is required"];
    } else if (!validator.isEmail(email)) {
      errors.email = ["Email is invalid"];
    }

    if (!password) {
      errors.password = ["Password is required"];
    } else if (password.length < 6) {
      errors.password = ["Password must be at least 6 characters"];
    }

    if (Object.keys(errors).length > 0) {
      return res.status(422).json({ success: false, errors });
    }

    // Check email existence
    const { data: existingUser, error: checkError } = await supabaseClient
      .from("users")
      .select("email")
      .eq("email", email.toLowerCase())
      .maybeSingle();

    if (checkError) {
      return res.status(500).json({
        success: false,
        message: "Database error"
      });
    }

    if (existingUser) {
      return res.status(422).json({
        success: false,
        errors: { email: ["Email already exists"] }
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const { data, error } = await supabaseClient
      .from("users")
      .insert([{
        full_name: full_name.trim(),
        email: email.toLowerCase(),
        password: hashedPassword
      }])
      .select("user_id, full_name, email, created_at");

    if (error) {
      return res.status(500).json({
        success: false,
        message: error.message
      });
    }

    res.status(201).json({
      success: true,
      message: "User created successfully",
      data: data[0]
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: err.message
    });
  }
};

// UPDATE user
export const updateUser = async (req, res) => {
  try {
    const { user_id } = req.params;
    const { full_name, email, password } = req.body;
    const errors = {};

    // Validation
    if (full_name !== undefined && !full_name?.trim()) {
      errors.full_name = ["Full name is required"];
    }

    if (email !== undefined) {
      if (!email) {
        errors.email = ["Email is required"];
      } else if (!validator.isEmail(email)) {
        errors.email = ["Email is invalid"];
      }
    }

    if (password !== undefined) {
      if (!password) {
        errors.password = ["Password is required"];
      } else if (password.length < 6) {
        errors.password = ["Password must be at least 6 characters"];
      }
    }

    if (Object.keys(errors).length > 0) {
      return res.status(422).json({ success: false, errors });
    }

    // Check if user exists
    const { data: existingUser, error: checkUserError } = await supabaseClient
      .from("users")
      .select("user_id")
      .eq("user_id", user_id)
      .maybeSingle();

    if (checkUserError) {
      return res.status(500).json({
        success: false,
        message: "Database error"
      });
    }

    if (!existingUser) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    // Check email uniqueness (if email is being updated)
    if (email) {
      const { data: emailExists, error: emailCheckError } = await supabaseClient
        .from("users")
        .select("user_id")
        .eq("email", email.toLowerCase())
        .neq("user_id", user_id)
        .maybeSingle();

      if (emailCheckError) {
        return res.status(500).json({
          success: false,
          message: "Database error"
        });
      }

      if (emailExists) {
        return res.status(422).json({
          success: false,
          errors: { email: ["Email already exists"] }
        });
      }
    }

    // Prepare update data
    const updateData = {};
    if (full_name !== undefined) updateData.full_name = full_name.trim();
    if (email !== undefined) updateData.email = email.toLowerCase();
    if (password !== undefined) {
      updateData.password = await bcrypt.hash(password, 10);
    }

    // Update user
    const { data, error } = await supabaseClient
      .from("users")
      .update(updateData)
      .eq("user_id", user_id)
      .select("user_id, full_name, email, created_at");

    if (error) {
      return res.status(500).json({
        success: false,
        message: error.message
      });
    }

    res.json({
      success: true,
      message: "User updated successfully",
      data: data[0]
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: err.message
    });
  }
};

export const deleteUser = async (req, res) => {
  try {
    const { user_id } = req.params;

    const { data, error } = await supabaseClient
      .from("users")
      .delete()
      .eq("user_id", user_id)
      .select("user_id, full_name, email");

    if (error) {
      console.error("SUPABASE DELETE ERROR:", error);
      return res.status(500).json({
        success: false,
        message: error.message,
      });
    }

    if (!data || data.length === 0) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    return res.json({
      success: true,
      message: "User deleted successfully",
      data: data[0],
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: err.message,
    });
  }
};
