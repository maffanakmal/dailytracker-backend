// OK

import slowDown from "express-slow-down";

export const registerSlowDown = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 2, // setelah 2 request
  delayMs: () => 1000, // tambah 1 detik tiap request
});

export default registerSlowDown;